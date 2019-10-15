package org.constellation.domain.p2p

import akka.http.scaladsl.model.StatusCodes
import cats.effect.{ContextShift, IO}
import cats.implicits._
import com.softwaremill.sttp.Response
import io.chrisdavenport.log4cats.slf4j.Slf4jLogger
import org.constellation.PeerMetadata
import org.constellation.domain.schema.Id
import org.constellation.p2p.{Cluster, PeerData}
import org.constellation.util.APIClient
import org.mockito.{ArgumentMatchersSugar, IdiomaticMockito}
import org.mockito.cats.IdiomaticMockitoCats
import org.scalatest.{BeforeAndAfter, FreeSpec, Matchers}

import scala.concurrent.ExecutionContext

class PeerHealthCheckTest
    extends FreeSpec
    with IdiomaticMockito
    with IdiomaticMockitoCats
    with Matchers
    with ArgumentMatchersSugar
    with BeforeAndAfter {
  implicit val contextShift: ContextShift[IO] = IO.contextShift(ExecutionContext.global)
  implicit val logger = Slf4jLogger.getLogger[IO]

  var cluster: Cluster[IO] = _
  var peerHealthCheck: PeerHealthCheck[IO] = _

  val peer1 = PeerData(
    mock[PeerMetadata],
    mock[APIClient],
    Seq.empty
  )

  val peer2 = PeerData(
    mock[PeerMetadata],
    mock[APIClient],
    Seq.empty
  )

  peer1.client.id shouldReturn Id("node1")
  peer2.client.id shouldReturn Id("node2")
  peer1.client.hostName shouldReturn "1.2.3.4"
  peer2.client.hostName shouldReturn "2.3.4.5"

  before {
    cluster = mock[Cluster[IO]]
    peerHealthCheck = PeerHealthCheck(cluster)
    cluster.removeDeadPeer(*) shouldReturnF Unit
  }

  "check" - {
    "should not remove peers if all are available" in {
      cluster.getPeerInfo shouldReturnF Map(Id("node1") -> peer1, Id("node2") -> peer2)
      peer1.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response.ok[String]("OK")
      peer2.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response.ok[String]("OK")

      peerHealthCheck.check().unsafeRunSync

      cluster.removeDeadPeer(*).wasNever(called)
    }

    "should remove unresponsive peer if peer is unhealthy" in {
      cluster.getPeerInfo shouldReturnF Map(Id("node1") -> peer1, Id("node2") -> peer2)
      peer1.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response.ok[String]("ERROR")
      peer2.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response.ok[String]("OK")

      peerHealthCheck.check().unsafeRunSync

      cluster.removeDeadPeer(*).was(called)
    }

    "should remove unresponsive peer if peer returned error" in {
      cluster.getPeerInfo shouldReturnF Map(Id("node1") -> peer1, Id("node2") -> peer2)
      peer1.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response.ok[String]("OK")
      peer2.client.getStringF[IO](*, *, *)(*)(*) shouldReturnF Response
        .error[String]("ERROR", 400, "400")

      peerHealthCheck.check().unsafeRunSync

      cluster.removeDeadPeer(*).was(called)
    }
  }
}