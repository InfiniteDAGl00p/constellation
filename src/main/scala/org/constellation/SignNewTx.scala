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

object LoadPemTest extends App{


  def parseEncryptedPrivPem(privateKeyFileName: String, password: String) = {
//    val privateKeyFile = new File(privateKeyFileName) // private key file in PEM format
    val reader = new FileReader("privateKeyFileName")//(privateKeyFile)
    val pemParser = new PEMParser(reader)
    val pemParserObj = pemParser.readObject().asInstanceOf[PEMEncryptedKeyPair]
    val decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray())
    val converter = new JcaPEMKeyConverter().setProvider("BC")
    val kp = converter.getKeyPair(pemParserObj.decryptKeyPair(decProv))
//    val test = kp
    kp.getPrivate
  }

  def parsePrivPem(reader: Reader): PrivateKey = {
    val pemParser = new PEMParser(reader)
    val pemKeyPair = pemParser.readObject().asInstanceOf[PEMKeyPair]
    new JcaPEMKeyConverter().getKeyPair(pemKeyPair).getPrivate
  }

  val password = "password"


  val bcProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider()

  val testKs: KeyStore = KeyStore.getInstance("PKCS12", bcProvider)
  testKs.load(null, password.toCharArray())

  val encryptedPath = "/Users/wyatt/.dag/encrypted_pem"
  val unencryptedPath = "/Users/wyatt/.dag/key"

  val loadedUnencrypted = parsePrivPem(new FileReader(unencryptedPath))


  testKs.store(new FileOutputStream(encryptedPath), password.toCharArray())

//  bks.store(new FileOutputStream(file), password)
  println(loadedUnencrypted)

//  def parseCertificate(reader: Reader): X509Certificate = {
//    val pemParser = new PEMParser(reader)
//    val certificate = pemParser.readObject().asInstanceOf[X509Certificate]
//    certificate
//  }

//  def write(os: OutputStream, privateKey: PrivateKey, password: Array[Char], certificate: X509Certificate): Unit = {
//    val keyStore = KeyStore.getInstance("pkcs12")
//    keyStore.load(null, password)
//
//    keyStore.setKeyEntry("1", privateKey, password, Seq(certificate).toArray)
//    keyStore.store(os, password)
//  }
}

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
  val privPemObj = new PemObject("EC PRIVATE KEY", aSN1Obj.getEncoded("DER"))//todo read keys from file and use new PemReader(new FileReader(keyFileName)

  if (true) {
    val decryptedFile = File(dagDir + "/private_decrypted.pem").toJava
    if (!decryptedFile.exists()) {
      decryptedFile.createNewFile()
    }
//    val decryptedOutput = new FileOutputStream(decryptedFile)
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

  val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
  val keyDir = dagDir + "/encrypted_key"
  val acctDir = dagDir + "/acct"

//  val p12File = better.files.File(keyDir + "keystoretest.p12").toJava
//  val bksFile = better.files.File(keyDir + "keystoretest.bks").toJava

  val (privKey, pubKey)  = WalletKeyStore.loadOrGetKeys(newTxData.pass)//testGetKeys()


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
//  println(signature.toString)
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
