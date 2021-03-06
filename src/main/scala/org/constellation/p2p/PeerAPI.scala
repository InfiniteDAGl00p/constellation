package org.constellation.p2p

import java.net.{InetSocketAddress, URI}

import akka.actor.ActorSystem
import akka.http.scaladsl.marshalling.Marshaller._
import akka.http.scaladsl.model._
import akka.http.scaladsl.server.Directives.{path, _}
import akka.http.scaladsl.server.{ExceptionHandler, Route}
import akka.http.scaladsl.unmarshalling.{FromEntityUnmarshaller, PredefinedFromEntityUnmarshallers}
import akka.util.Timeout
import better.files.File
import cats.effect.{ContextShift, IO}
import cats.implicits._
import com.softwaremill.sttp.Response
import com.typesafe.scalalogging.StrictLogging
import constellation._
import de.heikoseeberger.akkahttpjson4s.Json4sSupport
import org.constellation.CustomDirectives.IPEnforcer
import org.constellation.api.TokenAuthenticator
import org.constellation.consensus.{ConsensusRoute, _}
import org.constellation.domain.trust.TrustData
import org.constellation.primitives.Schema._
import org.constellation.primitives._
import org.constellation.schema.Id
import org.constellation.serializer.KryoSerializer
import org.constellation.util._
import org.constellation.{ConfigUtil, ConstellationExecutionContext, DAO, ResourceInfo}
import org.json4s.native
import org.json4s.native.Serialization

import scala.concurrent.Future
import scala.util.Random

case class PeerAuthSignRequest(salt: Long)

case class PeerRegistrationRequest(
  host: String,
  port: Int,
  id: Id,
  resourceInfo: ResourceInfo,
  majorityHeight: Option[Long],
  isGenesis: Boolean
)

case class PeerUnregister(host: String, port: Int, id: Id, majorityHeight: Long)

object PeerAPI {

  case class EdgeResponse(
    soe: Option[SignedObservationEdge] = None,
    cb: Option[CheckpointCache] = None
  )

}

class PeerAPI(override val ipManager: IPManager[IO])(
  implicit system: ActorSystem,
  val timeout: Timeout,
  val dao: DAO
) extends Json4sSupport
    with CommonEndpoints
    with IPEnforcer
    with StrictLogging
    with SimulateTimeoutDirective
    with TokenAuthenticator {

  implicit val serialization: Serialization.type = native.Serialization

  implicit val stringUnmarshaller: FromEntityUnmarshaller[String] =
    PredefinedFromEntityUnmarshallers.stringUnmarshaller

  implicit def exceptionHandler: ExceptionHandler =
    ExceptionHandler {
      case e: Exception =>
        extractUri { uri =>
          logger.error(s"Request to $uri could not be handled normally", e)
          complete(HttpResponse(StatusCodes.InternalServerError, entity = e.getMessage))
        }
    }

  val snapshotHeightRedownloadDelayInterval =
    ConfigUtil.constellation.getInt("snapshot.snapshotHeightRedownloadDelayInterval")

  private val authEnabled: Boolean = ConfigUtil.getAuthEnabled

  private def signEndpoints(socketAddress: InetSocketAddress) =
    post {
      path("status") {
        entity(as[SetNodeStatus]) { sns =>
          APIDirective.handle {
            if (sns.nodeStatus == NodeState.Offline) {
              dao.cluster.markOfflinePeer(sns.id)
            } else {
              dao.cluster.setNodeStatus(sns.id, sns.nodeStatus)
            }
          }(_ => complete(StatusCodes.OK))
        }
      } ~
        path("sign") {
          entity(as[PeerAuthSignRequest]) { e =>
            val hash = e.salt.toString

            val signature = hashSign(hash, dao.keyPair)
            complete(SingleHashSignature(hash, signature))
          }
        } ~
        path("register") {
          APIDirective.extractIP(socketAddress) { ip =>
            entity(as[PeerRegistrationRequest]) { request =>
              logger.debug(
                s"Received peer registration request $request on $ip"
              )
              logger.debug("Parsed host, sending peer manager request")
              APIDirective.handle(dao.cluster.pendingRegistration(ip, request))(
                _ => complete(StatusCodes.OK)
              )
            }
          }
        } ~
        path("join") {
          entity(as[HostPort]) { hp =>
            (IO
              .contextShift(ConstellationExecutionContext.bounded)
              .shift >> dao.cluster.join(hp)).unsafeRunAsyncAndForget
            complete(StatusCodes.OK)
          }
        } ~
        path("leave") {
          (IO
            .contextShift(ConstellationExecutionContext.bounded)
            .shift >> dao.cluster.leave(IO.unit)).unsafeRunAsyncAndForget
          complete(StatusCodes.OK)
        }
    } ~
      get {
        pathPrefix("registration") {
          path("request") {
            APIDirective.handle(dao.cluster.pendingRegistrationRequest)(complete(_))
          }
        }
      }

  private[p2p] def postEndpoints(socketAddress: InetSocketAddress) =
    post {
      path("joinedHeight") {
        entity(as[JoinedHeight]) { request =>
          val updatePeer = dao.cluster.updateJoinedHeight(request)

          APIDirective.handle(updatePeer)(_ => complete(StatusCodes.OK))
        }
      } ~
        path("deregister") {
          entity(as[PeerUnregister]) { request =>
            APIDirective.handle(dao.cluster.deregister(request)) { _ =>
              complete(StatusCodes.OK)
            }
          }
        } ~
        pathPrefix("request") {
          path("signature") {
            APIDirective.extractIP(socketAddress) { ip =>
              entity(as[SignatureRequest]) { sr =>
                onComplete(
                  EdgeProcessor.handleSignatureRequest(sr)
                ) { result =>
                  complete(result.toOption.flatMap(_.toOption))
                }
              }
            }
          }
        } ~
        pathPrefix("finished") {
          path("checkpoint") {

            APIDirective.extractIP(socketAddress) { ip =>
              entity(as[FinishedCheckpoint]) { fc =>
                optionalHeaderValueByName("ReplyTo") { replyToOpt =>
                  val baseHash = fc.checkpointCacheData.checkpointBlock.baseHash
                  logger.debug(
                    s"Handle finished checkpoint for cb: ${baseHash} and replyTo: $replyToOpt"
                  )

                  dao.metrics.incrementMetric("peerApiRXFinishedCheckpoint")

                  val cs: ContextShift[IO] = IO.contextShift(ConstellationExecutionContext.unbounded)
                  val bcs: ContextShift[IO] = IO.contextShift(ConstellationExecutionContext.bounded)

                  // TODO: makeCallback returns side-effectful Future inside IO.map
                  val callback = dao.checkpointAcceptanceService.acceptWithNodeCheck(fc)(cs).map { result =>
                    replyToOpt
                      .map(URI.create)
                      .map { u =>
                        logger.debug(
                          s"Making callback to: ${u.toURL} acceptance of cb: ${fc.checkpointCacheData.checkpointBlock.baseHash} performed $result"
                        )
                        makeCallback(u, FinishedCheckpointResponse(true))
                      }
                  }

                  val io = dao.snapshotService.getNextHeightInterval.flatMap { res =>
                    (res, fc.checkpointCacheData.height) match {
                      case (_, None) =>
                        IO { logger.warn(s"Missing height when accepting block $baseHash") } >>
                          StatusCodes.BadRequest.pure[IO]
                      case (2, _) => // TODO: hardcoded snapshot interval
                        callback.start(bcs) >> complete(StatusCodes.Accepted).pure[IO]
                      case (nextHeight, Some(Height(min, max))) if nextHeight > min =>
                        IO {
                          logger.debug(
                            s"Handle finished checkpoint for cb: ${fc.checkpointCacheData.checkpointBlock.baseHash} height condition not met next interval: ${nextHeight} received: ${fc.checkpointCacheData.height.get.min}"
                          )
                        } >> StatusCodes.Conflict.pure[IO]
                      case (_, _) =>
                        callback.start(bcs) >> StatusCodes.Accepted.pure[IO]
                    }
                  }

                  APIDirective.handle(io)(complete(_))
                }
              }
            }
          } ~
            path("reply") {
              entity(as[FinishedCheckpointResponse]) { fc =>
                if (!fc.isSuccess) {
                  dao.metrics.incrementMetric(
                    "formCheckpointSignatureResponseError"
                  )
                  logger.warn("Failure gathering signature")
                }
                complete(StatusCodes.OK)
              }
            }
        }
    }
  private val blockBuildingRoundRoute =
    createRoute(ConsensusRoute.pathPrefix)(
      () =>
        new ConsensusRoute(dao.consensusManager, dao.snapshotService, dao.transactionService, dao.backend)
          .createBlockBuildingRoundRoutes()
    )

  private[p2p] def mixedEndpoints(socketAddress: InetSocketAddress) =
    path("transaction") {
      put {
        entity(as[TransactionGossip]) { gossip =>
          logger.debug(s"Received transaction tx=${gossip.hash} with path=${gossip.path}")
          dao.metrics.incrementMetric("transactionRXByPeerAPI")

          implicit val random: Random = scala.util.Random

          /* TEMPORARY DISABLED todo: enable ignored tests as well org/constellation/p2p/PeerAPITest.scala:196
          val rebroadcast = for {
            tcd <- dao.transactionGossiping.observe(TransactionCacheData(gossip.tx, path = gossip.path))
            peers <- dao.transactionGossiping.selectPeers(tcd)
            peerData <- dao.peerInfo.map(_.filterKeys(peers.contains).values.toList)
            _ <- contextShift.evalOn(ConstellationExecutionContext.callbacks)(
              peerData.traverse(_.client.putAsync("transaction", TransactionGossip(tcd)))
            )
            _ <- dao.metrics.incrementMetricAsync[IO]("transactionGossipingSent")
          } yield ()

          rebroadcast.unsafeRunAsyncAndForget()
           */

          (IO.contextShift(ConstellationExecutionContext.bounded).shift >> dao.transactionGossiping.observe(
            TransactionCacheData(gossip.tx, path = gossip.path)
          )).unsafeRunAsyncAndForget()

          complete(StatusCodes.OK)
        }
      }
    } ~ get {
      path("trust") {
        APIDirective.handle(
          dao.trustManager.getPredictedReputation.flatMap { predicted =>
            if (predicted.isEmpty) dao.trustManager.getStoredReputation.map(TrustData)
            else TrustData(predicted).pure[IO]
          }
        )(complete(_))
      }

    }

  def routes(socketAddress: InetSocketAddress): Route =
    APIDirective.extractIP(socketAddress) { ip =>
      decodeRequest {
        encodeResponse {
          if (authEnabled) {
            authenticateBasic(realm = "basic realm", basicTokenAuthenticator) { _ =>
              peerApiRoutes(socketAddress, ip)
            }
          } else {
            peerApiRoutes(socketAddress, ip)
          }
        }
      }
    }

  private def peerApiRoutes(socketAddress: InetSocketAddress, ip: String): Route =
    signEndpoints(socketAddress) ~ commonEndpoints ~ batchEndpoints ~
      withSimulateTimeout(dao.simulateEndpointTimeout)(ConstellationExecutionContext.unbounded) {
        enforceKnownIP(ip) {
          postEndpoints(socketAddress) ~ mixedEndpoints(socketAddress) ~ blockBuildingRoundRoute
        }
      }

  private[p2p] def makeCallback(u: URI, entity: AnyRef): Future[Response[Unit]] =
    APIClient(u.getHost, u.getPort)(dao.backend, dao)
      .postNonBlockingUnit(u.getPath, entity)

  private def createRoute(path: String)(routeFactory: () => Route): Route =
    pathPrefix(path) {
      handleExceptions(exceptionHandler) {
        routeFactory()
      }
    }

  def idLookup(host: String): IO[Option[PeerData]] =
    dao.cluster.getPeerData(host)
}

case class IpIdMappingException(ip: String, port: Int) extends Exception(s"Unable to map ip: $ip to Id")
