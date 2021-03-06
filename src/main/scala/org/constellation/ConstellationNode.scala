package org.constellation

import java.net.InetSocketAddress
import java.security.KeyPair

import akka.actor.ActorSystem
import akka.http.scaladsl.Http
import akka.http.scaladsl.server.Directive0
import akka.http.scaladsl.server.directives.{DebuggingDirectives, LoggingMagnet}
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.Sink
import better.files._
import cats.effect.{ContextShift, ExitCode, IO, IOApp, Sync}
import cats.implicits._
import com.typesafe.config.{Config, ConfigFactory}
import com.typesafe.scalalogging.StrictLogging
import constellation._
import io.chrisdavenport.log4cats.Logger
import io.chrisdavenport.log4cats.slf4j.Slf4jLogger
import org.constellation.CustomDirectives.printResponseTime
import org.constellation.datastore.SnapshotTrigger
import org.constellation.domain.configuration.{CliConfig, NodeConfig}
import org.constellation.infrastructure.configuration.CliConfigParser
import org.constellation.keytool.KeyStoreUtils
import org.constellation.p2p.PeerAPI
import org.constellation.primitives.Schema.{NodeState, ValidPeerIPData}
import org.constellation.primitives._
import org.constellation.util.{APIClient, AccountBalance, AccountBalanceCSVReader, Metrics}
import org.slf4j.MDC

import scala.concurrent.{ExecutionContext, ExecutionContextExecutor, Future}
import scala.util.Try

/**
  * Main entry point for starting a node
  */
object ConstellationNode extends IOApp {
  implicit val logger: Logger[IO] = Slf4jLogger.getLogger[IO]

  final val LocalConfigFile = "local_config"
  final val preferencesPath = ".dag"

  import constellation._

  implicit val system: ActorSystem = ActorSystem("Constellation")
  implicit val materializer: ActorMaterializer = ActorMaterializer()
  implicit val executionContext: ExecutionContext = ConstellationExecutionContext.bounded

  def run(args: List[String]): IO[ExitCode] =
    for {
      _ <- logger.info(s"Main init with args $args")

      cliConfig <- CliConfigParser.parseCliConfig[IO](args)
      _ <- logger.info(s"CliConfig: $cliConfig")

      config = ConfigFactory.load() // TODO

      _ <- createPreferencesPath[IO](preferencesPath)

      nodeConfig <- getNodeConfig[IO](cliConfig, config)
      _ = new ConstellationNode(nodeConfig)

      exitCode = ExitCode.Success
    } yield exitCode

  private def getHostName[F[_]: Sync](cliConfig: CliConfig): F[String] = Sync[F].delay {
    Option(cliConfig.externalIp)
      .map(_.getHostAddress)
      .getOrElse(Try(File(LocalConfigFile).lines.mkString.x[LocalNodeConfig].externalIP).getOrElse("127.0.0.1"))
  }

  private def getAllocAccountBalances[F[_]: Sync](cliConfig: CliConfig): F[Seq[AccountBalance]] = Sync[F].delay {
    Try(new AccountBalanceCSVReader(cliConfig.allocFilePath).read()).getOrElse(Seq.empty)
  }

  private def createPreferencesPath[F[_]: Sync](path: String) = Sync[F].delay {
    File(path).createDirectoryIfNotExists()
  }

  private def getPort[F[_]: Sync](config: Config, fromArg: Option[Int], env: String, configPath: String): F[Int] =
    Sync[F].delay {
      fromArg.getOrElse(Option(System.getenv(env)).map(_.toInt).getOrElse(config.getInt(configPath)))
    }

  private def getKeyPair[F[_]: Sync](cliConfig: CliConfig): F[KeyPair] =
    KeyStoreUtils
      .keyPairFromStorePath(cliConfig.keyStorePath, cliConfig.alias)
      .value
      .flatMap({
        case Right(keyPair) => keyPair.pure[F]
        case Left(e)        => e.raiseError[F, KeyPair]
      })

  private def getNodeConfig[F[_]: Sync](cliConfig: CliConfig, config: Config): F[NodeConfig] =
    for {
      seeds <- CliConfigParser.loadSeedsFromConfig(config)
      logger <- Slf4jLogger.create[F]

      _ <- logger.debug(s"Seeds: $seeds")

      keyPair <- getKeyPair(cliConfig)

      hostName <- getHostName(cliConfig)

      portOffset = Option(cliConfig.externalPort).filter(_ != 0)
      httpPortFromArg = portOffset
      peerHttpPortFromArg = portOffset.map(_ + 1)

      httpPort <- getPort(config, httpPortFromArg, "DAG_HTTP_PORT", "http.port")
      peerHttpPort <- getPort(config, peerHttpPortFromArg, "DAG_PEER_HTTP_PORT", "http.peer-port")

      allocAccountBalances <- getAllocAccountBalances(cliConfig)
      _ <- logger.debug(s"Alloc: $allocAccountBalances")

      constellationConfig = config.getConfig("constellation")
      processingConfig = ProcessingConfig(maxWidth = constellationConfig.getInt("max-width"))

      nodeConfig = NodeConfig(
        seeds = seeds,
        primaryKeyPair = keyPair,
        isGenesisNode = cliConfig.genesisNode,
        isLightNode = cliConfig.lightNode,
        hostName = hostName,
        httpInterface = config.getString("http.interface"),
        httpPort = httpPort,
        peerHttpPort = peerHttpPort,
        defaultTimeoutSeconds = config.getInt("default-timeout-seconds"),
        attemptDownload = !cliConfig.genesisNode,
        cliConfig = cliConfig,
        processingConfig =
          if (cliConfig.testMode) ProcessingConfig.testProcessingConfig.copy(maxWidth = 10) else processingConfig,
        dataPollingManagerOn = config.getBoolean("constellation.dataPollingManagerOn"),
        allocAccountBalances = allocAccountBalances
      )
    } yield nodeConfig
}

class ConstellationNode(
  val nodeConfig: NodeConfig = NodeConfig()
)(
  implicit val system: ActorSystem,
  implicit val materialize: ActorMaterializer
//  implicit val executionContext: ExecutionContext
) extends StrictLogging {

  implicit val dao: DAO = new DAO()
  dao.nodeConfig = nodeConfig
  dao.metrics = new Metrics(periodSeconds = nodeConfig.processingConfig.metricCheckInterval)
  dao.initialize(nodeConfig)

  dao.node = this

  MDC.put("node_id", dao.id.short)

  dao.eigenTrust.initializeModel().unsafeRunSync()
  dao.eigenTrust.registerSelf().unsafeRunSync()

  logger.info(
    s"Node init with API ${nodeConfig.httpInterface} ${nodeConfig.httpPort} peerPort: ${nodeConfig.peerHttpPort}"
  )

  val ipManager: IPManager[IO] =
    IPManager[IO]()(IO.ioConcurrentEffect(IO.contextShift(ConstellationExecutionContext.bounded)))

  nodeConfig.seeds.foreach { peer =>
    dao.ipManager.addKnownIP(peer.host)
  }

  // TODO: Unused, can be used for timing information but adds a lot to logs
  private val logReqResp: Directive0 = DebuggingDirectives.logRequestResult(
    LoggingMagnet(printResponseTime(logger))
  )

  // If we are exposing rpc then create routes
  val api: API = new API()(system, constellation.standardTimeout, dao)

  logger.info("Binding API")

  // Setup http server for internal API
  val apiBinding: Future[Http.ServerBinding] = Http()
    .bind(nodeConfig.httpInterface, nodeConfig.httpPort)
    .to(Sink.foreach { conn =>
      val address = conn.remoteAddress
      conn.handleWith(api.routes(address))
    })
    .run()

  val peerAPI = new PeerAPI(dao.ipManager)

  def getIPData: ValidPeerIPData =
    ValidPeerIPData(nodeConfig.hostName, nodeConfig.peerHttpPort)

  def getInetSocketAddress: InetSocketAddress =
    new InetSocketAddress(nodeConfig.hostName, nodeConfig.peerHttpPort)

  // Setup http server for peer API
  val peerApiBinding: Future[Http.ServerBinding] = Http()
    .bind(nodeConfig.httpInterface, nodeConfig.peerHttpPort)
    .to(Sink.foreach { conn =>
      val address = conn.remoteAddress
      conn.handleWith(peerAPI.routes(address))
    })
    .run()

  def shutdown(): Unit = {

    val unbindTimeout = ConfigUtil.getDurationFromConfig("akka.http.unbind-api-timeout")

    implicit val ec: ExecutionContextExecutor = ConstellationExecutionContext.unbounded
    implicit val cs: ContextShift[IO] = IO.contextShift(ec)

    val gracefulShutdown = IO(logger.info("Shutdown procedure starts")) >>
      IO.fromFuture(IO(peerApiBinding.flatMap(_.terminate(unbindTimeout)))) >>
      IO.fromFuture(IO(apiBinding.flatMap(_.terminate(unbindTimeout)))) >>
      IO.fromFuture(IO(system.terminate())) >>
      IO(logger.info("Shutdown completed"))

    dao.cluster
      .leave(gracefulShutdown.void)
      .unsafeRunSync()
  }

  //////////////

  // TODO : Move to separate test class - these are within jvm only but won't hurt anything
  // We could also consider creating a 'Remote Proxy class' that represents a foreign
  // ConstellationNode (i.e. the current Peer class) and have them under a common interface

  def getAPIClient(host: String = nodeConfig.hostName, port: Int = nodeConfig.httpPort): APIClient = {
    val api = APIClient(host, port)(dao.backend, dao)
    api.id = dao.id
    api
  }

  def getPeerAPIClient: APIClient = {
    val api = APIClient(dao.nodeConfig.hostName, dao.nodeConfig.peerHttpPort)(dao.backend, dao)
    api.id = dao.id
    api
  }

  // TODO: Change E2E to not use this but instead rely on peer discovery, need to send addresses there too
  def getAddPeerRequest: PeerMetadata =
    PeerMetadata(
      nodeConfig.hostName,
      nodeConfig.peerHttpPort,
      dao.id,
      auxAddresses = dao.addresses,
      nodeType = dao.nodeType,
      resourceInfo = ResourceInfo(
        diskUsableBytes = new java.io.File(dao.snapshotPath).getUsableSpace
      )
    )

  def getAPIClientForNode(node: ConstellationNode): APIClient = {
    val ipData = node.getIPData
    val api = APIClient(host = ipData.canonicalHostName, port = ipData.port)(dao.backend, dao)
    api.id = dao.id
    api
  }

  logger.info("Node started")

  // TODO: Use this for full flow, right now this only works as a debugging measure, does not integrate properly
  // with other nodes joining
  if (nodeConfig.isGenesisNode) {
    logger.info("Creating genesis block")
    Genesis.start()
    logger.info(s"Genesis block hash ${dao.genesisBlock.map { _.soeHash }.getOrElse("")}")

    dao.cluster.compareAndSet(NodeState.initial, NodeState.Ready).unsafeRunAsync(_ => ())
  }

  dao.cluster.initiateRejoin().unsafeRunSync

//  Keeping disabled for now -- going to only use midDb for the time being.
//  private val txMigrator = new TransactionPeriodicMigration

  var dataPollingManager: DataPollingManager = _
  if (nodeConfig.dataPollingManagerOn) {
    dataPollingManager = new DataPollingManager(60)
  }
}
