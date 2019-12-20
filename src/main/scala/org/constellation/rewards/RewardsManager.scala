package org.constellation.rewards

import cats.effect._
import cats.effect.concurrent.Ref
import cats.implicits._
import org.constellation.checkpoint.CheckpointService
import org.constellation.consensus.Snapshot
import org.constellation.domain.observation.Observation
import org.constellation.p2p.PeerNotification
import org.constellation.primitives.Schema.{AddressCacheData, CheckpointEdge}
import org.constellation.primitives.{ChannelMessage, Transaction}
import org.constellation.rewards.RewardsManager.rewardDuringEpoch
import org.constellation.storage.AddressService
import org.constellation.trust.TrustEdge

class RewardsManager[F[_]: Concurrent](
  eigenTrust: EigenTrust[F],
  checkpointService: CheckpointService[F],
  addressService: AddressService[F]
) {
  final val rewards: Ref[F, Map[String, Double]] = Ref.unsafe(Map.empty)

  def updateBySnapshot(snapshot: Snapshot, snapshotNum: Int): F[Unit] =
    for {
      observations <- observationsFromSnapshot(snapshot)
      _ <- eigenTrust.retrain(observations)

      hashesTrustMap <- eigenTrust.getTrustForAddressHashes

      distribution = RewardsManager
        .rewardDistribution(hashesTrustMap.keys.toSeq, hashesTrustMap)
        .mapValues(_ * rewardDuringEpoch(snapshotNum))

      _ <- updateRewards(distribution)
      _ <- updateAddressBalances(distribution)
    } yield ()

  private def observationsFromSnapshot(snapshot: Snapshot): F[Seq[Observation]] =
    snapshot.checkpointBlocks.toList
      .traverse(checkpointService.fullData)
      .map(_.flatten.flatMap(_.checkpointBlock.observations))

  private def updateRewards(distribution: Map[String, Double]): F[Unit] =
    rewards.modify(prevDistribution => (prevDistribution |+| distribution, ()))

  /*
    TODO: Not sure if it is the correct way of updating balances by rewards.
    1. putUnsafe takes Account.hash but we pass there Id.address which could differ. Maybe we should do Address(id.address).hash.
    2. I take the current balance and just copy the balance by adding rewards. Seems to be quite... dirty and unsafe?
   */
  private def updateAddressBalances(rewards: Map[String, Double]): F[Unit] =
    rewards.transform {
      case (address, reward) =>
        addressService.lookup(address).flatMap { existingCacheData =>
          val updatedAddressCacheData = existingCacheData.map(
            cache =>
              cache.copy(
                balance = cache.balance + reward.toLong,
                memPoolBalance = cache.memPoolBalance + reward.toLong
              )
          ).getOrElse(AddressCacheData(reward.toLong, reward.toLong))

          addressService.putUnsafe(address, updatedAddressCacheData)
        }
    }.values.toList.sequence.void
}

object RewardsManager {
  val roundingError = 0.000000000001

  /*
  Rewards computed about one snapshots per 3 minutes, i.e. about 14,600 snapshots per month.
  Snapshots for a first epoch of 2.5 years.
   */
  val epochOne = 438000 // = 14,600 snapshots per month * 12 months per year * 2.5 years
  val epochTwo = 876000 // = 2 * epochOne (5 years)
  val epochThree = 1314000 // = 3 * epochOne (7.5 years)
  val epochFour = 1752000 // = 4 * epochOne (10 years)
  val rewardsPool = epochFour

  /*
  10,000 units per month.
   */
  val epochOneRewards = 0.68493150684 // = 10,000 / 14,600
  val epochTwoRewards = 0.34246575342 // = epochOneRewards / 2
  val epochThreeRewards = 0.17123287671 // = epochTwoRewards / 2
  val epochFourRewards = 0.08561643835 // = epochThreeRewards / 2

  /*
  Partitioning of address space, light nodes have smaller basis that full.
  Normalizes rewards based on node size.
   */
  val partitonChart = Map[String, Set[String]]()

  /*
  Should come from reputation service.
   */
  val transitiveReputationMatrix = Map[String, Map[String, Double]]()
  val neighborhoodReputationMatrix = Map[String, Double]()

  def validatorRewards(
    curShapshot: Int,
    transitiveReputationMatrix: Map[String, Map[String, Double]],
    neighborhoodReputationMatrix: Map[String, Double],
    partitonChart: Map[String, Set[String]]
  ) = {
    val trustEntropyMap = shannonEntropy(transitiveReputationMatrix, neighborhoodReputationMatrix)
    val distro = rewardDistribution(partitonChart, trustEntropyMap)
    distro.mapValues(_ * rewardDuringEpoch(curShapshot))
  }

  def rewardDuringEpoch(curShapshot: Int) = curShapshot match {
    case num if num >= 0 && num < epochOne           => epochOneRewards
    case num if num >= epochOne && num < epochTwo    => epochTwoRewards
    case num if num >= epochTwo && num < epochThree  => epochThreeRewards
    case num if num >= epochThree && num < epochFour => epochFourRewards
    case _                                           => 0d
  }

  def shannonEntropy(
    transitiveReputationMatrix: Map[String, Map[String, Double]],
    neighborhoodReputationMatrix: Map[String, Double]
  ) = {
    val weightedTransitiveReputation = transitiveReputationMatrix.transform {
      case (key, view) => view.map { case (neighbor, score) => neighborhoodReputationMatrix(key) * score }.sum
    }
    weightedTransitiveReputation.mapValues { trust =>
      if (trust == 0.0) 0.0
      else -trust * math.log(trust) / math.log(2)
    }
  }

  def weightContributions(
    contributions: Map[String, Double],
    trustEntropyMap: Map[String, Double]
  ): Map[String, Double] = {
    val weightedEntropy = contributions.transform {
      case (address, partitionSize) =>
        partitionSize * (1 - trustEntropyMap(address)) // Normalize wrt total partition space
    }
    val totalEntropy = weightedEntropy.values.sum
    weightedEntropy.mapValues(_ / totalEntropy) // Scale by entropy magnitude
  }

  def rewardDistribution(addresses: Seq[String], trustEntropyMap: Map[String, Double]): Map[String, Double] = {
    val totalSpace = addresses.size
    val contribution = 1.0 / totalSpace
    val contributions = addresses.map { address =>
      address -> contribution
    }.toMap
    weightContributions(contributions, trustEntropyMap)
  }

  def rewardDistribution(
    partitonChart: Map[String, Set[String]],
    trustEntropyMap: Map[String, Double]
  ): Map[String, Double] = {
    val totalSpace = partitonChart.values.map(_.size).max
    val contributions = partitonChart.mapValues(partiton => (partiton.size / totalSpace).toDouble)
    weightContributions(contributions, trustEntropyMap)
  }

  /*
 If nodes deviate more than x% from the accepted checkpoint block, drop to 0?
   */
  def performanceExperience(cps: Seq[MetaCheckpointBlock]): Map[Int, Double] = {
    val facilDiffsPerRound = cps.flatMap { cb =>
      val acceptedCbHashes = cb.transactions.map(_.hash).toSet //todo combine in all data hashes, currently tx check
      cb.proposals.mapValues { proposedCb: Set[String] =>
        val diff = acceptedCbHashes.diff(proposedCb)
        diff.size
      }
    }
    val facilDiffs
      : Map[Int, Seq[(Int, Int)]] = facilDiffsPerRound.groupBy { case (facilitator, diff) => facilitator } //.mapValues(v => v / cpb.size.toDouble)
    facilDiffs.mapValues { fd =>
      val acceptedCbTxHashes = cps.flatMap(_.transactions.map(_.hash).toSet)
      fd.map(_._2).sum / acceptedCbTxHashes.size.toDouble

    }
  }

  case class TestCheckpointBlock(proposals: Map[Int, Set[String]], acceptedCb: Set[String])

  case class MetaCheckpointBlock(
    proposals: Map[Int, Set[String]], //todo use Id instead of Int, see below
    trustEdges: Option[Map[Int, Seq[TrustEdge]]], //todo use actual Ids in SAW
    transactions: Seq[Transaction],
    checkpoint: CheckpointEdge,
    messages: Seq[ChannelMessage] = Seq(),
    notifications: Seq[PeerNotification] = Seq()
  ) //extends CheckpointBlock(transactions, checkpoint)
}
