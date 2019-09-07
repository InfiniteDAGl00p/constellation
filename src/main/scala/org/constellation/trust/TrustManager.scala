package org.constellation.trust

import com.typesafe.scalalogging.StrictLogging
import constellation.futureTryWithTimeoutMetric
import org.constellation.DAO
import org.constellation.primitives.Schema.Id
import org.constellation.util.Periodic

import scala.concurrent.{ExecutionContextExecutor, Future}
import scala.util.Try


/**
  * Periodic trust polling agent for getting other nodes scores and recalculating walk
  * @param periodSeconds: Time to re-run batch calculation
  * @param dao: Data access object
  */
class TrustManager(periodSeconds: Int = 120)(implicit dao: DAO, ec: ExecutionContextExecutor)
  extends Periodic[Try[Unit]]("DataPollingManager", periodSeconds)
    with StrictLogging {

  private def execute() = {
    futureTryWithTimeoutMetric(
      {

        val peers = dao.readyPeers.unsafeRunSync().toSeq

        if (peers.nonEmpty) {

          val peerTrustScores = peers.map {
            case (id, pd) =>
              id -> pd.client.getBlocking[Map[Id, Double]]("trust")
          }

          val selfLabels = dao.publicReputation.toMap

          val scores: Seq[(Id, Map[Id, Double])] = peerTrustScores :+ (dao.id -> selfLabels)

          val idMap = (peers.map { _._1 } :+ dao.id).sortBy{_.hex}.zipWithIndex.toMap
          val idxMap = idMap.map { case (k, v) => v -> k }

          val nodes = scores.map {
            case (id, peerScores) =>
              val selfIdx = idMap(id)
              TrustNode(selfIdx, 0D, 0D, peerScores.map {
                case (peerId, score) =>
                  TrustEdge(selfIdx, idMap(peerId), score, id == dao.id)
              }.toSeq)

          }

          val selfUpdated = SelfAvoidingWalk.runWalkFeedbackUpdateSingleNode(idMap(dao.id), nodes)

          val idMappedScores = selfUpdated.edges.map { e =>
            idxMap(e.dst) -> e.trust
          }.toMap

          dao.predictedReputation = idMappedScores
        }

      },
      "trustPoll",
      60, {
        dao.metrics.incrementMetric("trustPollFailure")
      }
    )
  }

  override def trigger(): Future[Try[Unit]] = {
    if (dao.readyPeers.unsafeRunSync().nonEmpty) {
      execute()
    } else Future.successful(Try(Unit))
  }
}
