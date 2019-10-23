package org.constellation

import java.io
import java.io.{FileInputStream, FileOutputStream, FileReader}

import better.files.File
import constellation.{createTransaction, _}
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.util.io.pem.{PemObject, PemWriter}
import org.constellation.crypto.KeyUtils._
import org.constellation.primitives._
import org.spongycastle.openssl.{PEMEncryptedKeyPair, PEMKeyPair, PEMParser, PEMWriter}
import org.spongycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter
import java.io._
import java.security.cert.Certificate
import java.security.{KeyStore, PrivateKey, _}

import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.constellation.GetOrCreateKeys.{aSN1Obj, keyPair}
//import org.bouncycastle.jce.provider
import org.constellation.crypto.WalletKeyStore


class ASN1ObjectInstance(pKI: PrivateKeyInfo) extends ASN1Object {
  def toASN1Primitive = pKI.parsePrivateKey().toASN1Primitive

  override def getEncoded(str: String): Array[Byte] = super.getEncoded(str)
}

object GetOrCreateKeys
  extends App {

  def parsePrivPem(path: String): PrivateKey = {
    val reader = new FileReader(path)
    val pemParser = new PEMParser(reader)
    val pemKeyPair = pemParser.readObject().asInstanceOf[PEMKeyPair]
    new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate
  }

  def toASN1Obj(keyPair: KeyPair): ASN1ObjectInstance = {
    val privateKeyInfo: PrivateKeyInfo = PrivateKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPrivate.getEncoded))
    val isEC = privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)
    if (! isEC) {
      throw new Exception ("not EC key")
    } else {
      val getASN1: ASN1ObjectInstance = new ASN1ObjectInstance(privateKeyInfo)
      getASN1
    }
  }

  def pubToPem(keyPair: KeyPair) = {
    val aSN1Obj: ASN1ObjectInstance = toASN1Obj(keyPair)
    val pubPemPbj = new PemObject("EC PUBLIC KEY", aSN1Obj.getEncoded("DER"))
    pubPemPbj
  }

  val (password, unEncrypt) = args match {
    case Array(pw, storeUnencrypted) => (pw, storeUnencrypted.toBoolean)
    case Array(pw) => (pw, false)
    case Array() => ("fakepassword", false)
  }

  val dagDir = System.getProperty("user.home") + "/.dag" //todo dry by putting into own into files
  val acctDir = dagDir + "/acct"
  val keyDir = dagDir + "/key"
  val (privKey, pubKey) = WalletKeyStore.loadOrGetKeys(password)
  val keyPair = new KeyPair(pubKey, privKey)
  val privateKeyInfo: PrivateKeyInfo = PrivateKeyInfo.getInstance(ASN1Sequence.getInstance(keyPair.getPrivate.getEncoded))

  val aSN1Obj: ASN1ObjectInstance = toASN1Obj(keyPair)
  val decryptedKeyOutput = new FileOutputStream(dagDir + "/private_decrypted.pem")

  val pemWriter = new PemWriter(new OutputStreamWriter(decryptedKeyOutput))
  val privPemObj = new PemObject("EC PRIVATE KEY", aSN1Obj.getEncoded("DER"))

  if (unEncrypt) {
    val decryptedFile = File(dagDir + "/private_decrypted.pem").toJava
    if (!decryptedFile.exists()) decryptedFile.createNewFile()
    pemWriter.writeObject(privPemObj)
    pemWriter.close()
  }
}

object SignNewTx extends App {

  case class TxData(ammt: Long, dst: String, fee: Long = 0L, pass: String = "fakepassword")//todo: add logic for multiple keygen and key/acct storage

  val newTxData = args match {
    case Array(ammt, dst, fee, pass) => TxData(ammt.toLong, dst, fee.toLong, pass)
    case Array() => TxData(420, "local_test", 1L, "fakepassword")
  }

  val dagDir = System.getProperty("user.home") +"/.dag"
  val keyDir = dagDir + "/encrypted_key"
  val acctDir = dagDir + "/acct"

  val (privKey, pubKey)  = WalletKeyStore.loadOrGetKeys(newTxData.pass)//testGetKeys()
  val keyInfo = new KeyPair(pubKey, privKey)//GetOrCreateKeys

  val acctFile = File(acctDir)
  val (prevTxHash, prevTxCount) =
    if (acctFile.notExists)(fromBase64("baseHash"), 0L)
    else {
      val loadedTx = acctFile.lines.head.x[Transaction]
      (loadedTx.signature, loadedTx.count)
  }

  val src = publicKeyToHex(pubKey)
  val signature: Array[Byte] = signData(prevTxHash)(privKey)
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
