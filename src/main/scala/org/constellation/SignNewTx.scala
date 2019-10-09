package org.constellation

import java.io.{BufferedWriter, FileInputStream, FileOutputStream}

import better.files.File
import constellation.{createTransaction, _}
import org.constellation.crypto.KeyUtils._
import org.constellation.primitives._
import java.nio.file.Paths
import java.security._

import constellation._
import org.constellation.SignNewTx.{TxData, args}
//import org.constellation.GetOrCreateKeys.dagDir
import org.constellation.crypto.WalletKeyStore
import java.io._



object GetOrCreateKeys
  extends App {
  val (password, unEncrypt) = args match {
    case Array(pw, storeUnencrypted) => (pw, storeUnencrypted.toBoolean)
    case Array(pw) => (pw, false)
    case Array() => ("fakepassword", false)

  }
  val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
  val acctDir = dagDir + "/acct"
  val keyDir = dagDir + "/key"
  val (privKey, pubKey) = WalletKeyStore.testGetKeys(password)
  val keyPair = new KeyPair(pubKey, privKey)

  if (unEncrypt) {
    val decryptedFile = File(dagDir + "/decrypted").toJava
    if (!decryptedFile.exists()) {
      decryptedFile.createNewFile()
    }
    val output = new FileOutputStream(decryptedFile)
    output.write(keyPair.getPrivate.getEncoded)
    output.close()
  }
}

object SignNewTx extends App {
  import java.security.cert.CertificateFactory
  import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
  import java.security.{KeyFactory, SecureRandom, _}
  case class TxData(ammt: Long, dst: String, fee: Long = 0L, pass: String = "fakepassword")//todo: add logic for multiple keygen and key/acct storage

  val newTxData = args match {
    case Array(ammt, dst, fee, pass) => TxData(ammt.toLong, dst, fee.toLong, pass)
    case Array() => TxData(420, "local_test", 1L, "fakepassword")
  }

  val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
  val keyDir = dagDir + "/encrypted_key"
  val acctDir = dagDir + "/acct"

//  val p12File = better.files.File(keyDir + "keystoretest.p12").toJava
//  val bksFile = better.files.File(keyDir + "keystoretest.bks").toJava

  val (privKey, pubKey)  = WalletKeyStore.testGetKeys(newTxData.pass)//testGetKeys()


//  val p12 = KeyStore.getInstance("PKCS12", "BC")
//  p12.load(new java.io.FileInputStream(p12File), newTxData.pass.toCharArray)
//
//  val bks: KeyStore = KeyStore.getInstance("BKS", "BC")
//  bks.load(new FileInputStream(bksFile), newTxData.pass.toCharArray)
//
//  val privKey: PrivateKey = bks.getKey("test_rsa", newTxData.pass.toCharArray).asInstanceOf[PrivateKey]
//
//  val pubKey: PublicKey = p12.getCertificate("test_cert").getPublicKey


  val keyInfo = new KeyPair(pubKey, privKey)//GetOrCreateKeys


  val acctFile = File(acctDir)
  val (prevTxHash, prevTxCount) =
    if (acctFile.notExists)(fromBase64("baseHash"), 0L)
  else {
    val loadedTx = acctFile.lines.head.x[Transaction]
    (loadedTx.signature, loadedTx.count)
  }
  val src = publicKeyToHex(pubKey)//keyInfo.keyPair.getPublic)
  val signature: Array[Byte] = signData(prevTxHash)(privKey)//keyInfo.keyPair.getPrivate)
  println(signature.toString)
  val newTx = createTransaction(
    src,
    newTxData.dst,
    newTxData.ammt,
    keyInfo,
    prevTxCount + 1,
    true,
    false,
    newTxData.fee,
    signature)

  newTx.jsonAppend(acctDir)
}
