package org.constellation.trust

import cats.effect.IO
import cats.implicits._
import com.typesafe.config.Config
import org.constellation.{ConfigUtil, DAO}
import org.constellation.schema.Id
import org.constellation.domain.trust.{TrustData, TrustDataInternal}
import org.constellation.p2p.Cluster
import org.constellation.primitives.Schema.NodeState
import org.constellation.util.PeriodicIO

import scala.concurrent.duration._

class TrustDataPollingScheduler(
  config: Config,
  trustManager: TrustManager[IO],
  cluster: Cluster[IO],
  dao: DAO
) extends PeriodicIO("TrustDataPollingScheduler") {

  override def trigger(): IO[Unit] =
    cluster.getPeerInfo
      .map(_.filter(t => NodeState.validForLettingOthersDownload.contains(t._2.peerMetadata.nodeState)).values.toList)
      .flatMap(
        _.traverse(
          pd =>
            pd.client
              .getNonBlockingIO[TrustDataInternal]("trust")(IO.contextShift(taskPool))
              .handleError(_ => TrustDataInternal(pd.client.id, Map.empty[Id, Double]))
        )
      )
      .flatMap(trustManager.handleTrustScoreUpdate)
      .flatTap(_ => dao.metrics.incrementMetricAsync[IO]("trustDataPollingRound"))

  schedule(ConfigUtil.getDurationFromConfig("constellation.trust.pull-trust-interval", 60 seconds, config))

}

object TrustDataPollingScheduler {

  def apply(config: Config, trustManager: TrustManager[IO], cluster: Cluster[IO], dao: DAO) =
    new TrustDataPollingScheduler(config, trustManager, cluster, dao)
}
