package org.constellation.rollback

import better.files.File
import org.constellation.consensus.{SnapshotInfo, SnapshotInfoSer, StoredSnapshot, TipData}
import org.constellation.primitives.Schema.{AddressCacheData, CheckpointCache, GenesisObservation}
import org.constellation.serializer.KryoSerializer
import constellation._

import scala.util.Try

class RollbackLoader(
  snapshotsPath: String,
  snapshotInfoPath: String,
  genesisObservationPath: String
) {

  def loadSnapshotsFromFile(): Either[RollbackException, Seq[StoredSnapshot]] =
    Try(deserializeAllFromDirectory[StoredSnapshot](snapshotsPath))
      .map(Right(_))
      .getOrElse(Left(CannotLoadSnapshotsFiles(snapshotsPath)))

  def loadSnapshotInfoFromFile(): Either[RollbackException, SnapshotInfo] =
    Try(loadSnapshotInfoSer(File(snapshotInfoPath).parent.pathAsString)).toEither
      .map(Right(_))
      .getOrElse(Left(CannotLoadSnapshotInfoFile(snapshotInfoPath)))

  def loadSnapshotInfoSer(parentDirectory: String) = {
    val snapInfoSerParts: Map[String, Array[Array[Byte]]] = File(parentDirectory)
      .glob("**")
      .filter(_.pathAsString.contains("rollback_info"))
      .map { file =>
        val Array(parentDir, dataType, partId) = file.pathAsString.split("-")
        val loadedPartFile = File(file.pathAsString).byteArray
        (dataType, (partId, loadedPartFile))
      }
      .toSeq
      .groupBy(_._1)
      .mapValues { v =>
        v.map(_._2).sortBy(_._1.toInt).map(_._2).toArray
      }
    val serSnapInfo = SnapshotInfoSer(
      snapInfoSerParts("snapshot"),
      snapInfoSerParts("snapshotCheckpointBlocks"),
      snapInfoSerParts("acceptedCBSinceSnapshot"),
      snapInfoSerParts("acceptedCBSinceSnapshotCache"),
      snapInfoSerParts("lastSnapshotHeight"),
      snapInfoSerParts("snapshotHashes"),
      snapInfoSerParts("addressCacheData"),
      snapInfoSerParts("tips"),
      snapInfoSerParts("snapshotCache"),
      snapInfoSerParts("lastAcceptedTransactionRef")
    )
    serSnapInfo.toSnapshotInfo()
  }

  private def deserializeFromFile[T](path: String): T =
    KryoSerializer.deserializeCast[T](File(path).byteArray)

  private def deserializeAllFromDirectory[T](directory: String): Seq[T] =
    getListFilesFromDirectory(directory).map(s => deserializeFromFile[T](s))

  private def getListFilesFromDirectory(directory: String): Seq[File] =
    File(directory).list.toSeq

  private def deserializeFromFile[T](file: File): T =
    KryoSerializer.deserializeCast(file.byteArray)

  def loadGenesisObservation(): Either[RollbackException, GenesisObservation] =
    Try(deserializeFromFile[GenesisObservation](genesisObservationPath))
      .map(Right(_))
      .getOrElse(Left(CannotLoadGenesisObservationFile(genesisObservationPath)))
}
