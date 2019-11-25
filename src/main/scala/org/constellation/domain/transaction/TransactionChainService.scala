package org.constellation.domain.transaction

import cats.effect.{Concurrent, Sync}
import cats.effect.concurrent.Ref
import cats.implicits._
import io.chrisdavenport.log4cats.slf4j.Slf4jLogger
import org.constellation.consensus.{Snapshot, SnapshotInfo}
import org.constellation.primitives.Schema.TransactionEdgeData
import org.constellation.primitives.{Edge, Transaction}

class TransactionChainService[F[_]: Concurrent] {

  val logger = Slf4jLogger.getLogger[F]

  // TODO: Make sure to clean-up those properly
  private[domain] val lastTransactionRef: Ref[F, Map[String, LastTransactionRef]] = Ref.unsafe(Map.empty)
  private[domain] val lastAcceptedTransactionRef: Ref[F, Map[String, LastTransactionRef]] = Ref.unsafe(Map.empty)

  def getLastTransactionRef(address: String): F[LastTransactionRef] =
    lastTransactionRef.get.map(_.getOrElse(address, LastTransactionRef.empty))

  def getLastAcceptedTransactionRef(address: String): F[LastTransactionRef] =
    lastAcceptedTransactionRef.get.map(_.getOrElse(address, LastTransactionRef.empty))

  def getLastAcceptedTransactionMap(): F[Map[String, LastTransactionRef]] = lastAcceptedTransactionRef.get

  def acceptTransaction(tx: Transaction): F[Unit] =
    lastAcceptedTransactionRef.modify { m =>
      val address = tx.src.address
      (m + (address -> LastTransactionRef(tx.hash, tx.ordinal)), ())
    }

  def setLastTransaction(edge: Edge[TransactionEdgeData], isDummy: Boolean): F[Transaction] = {
    val address = edge.observationEdge.parents.head.hash

    lastTransactionRef.modify { m =>
      val ref = m.getOrElse(address, LastTransactionRef.empty)
      val tx = Transaction(edge, ref, isDummy)
      (m + (address -> LastTransactionRef(tx.hash, tx.ordinal)), tx)
    }
  }

  def applySnapshotInfo(snapshotInfo: SnapshotInfo): F[Unit] =
    lastAcceptedTransactionRef.modify { _ =>
      (snapshotInfo.lastAcceptedTransactionRef, ())
    }

}

object TransactionChainService {
  def apply[F[_]: Concurrent]: TransactionChainService[F] = new TransactionChainService[F]()
}