package org.constellation

import java.{io, util}
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
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyStore, PrivateKey, _}

import com.google.common.collect.ImmutableList
import org.bitcoinj.crypto.{ChildNumber, MnemonicCode}
import org.bitcoinj.wallet.Wallet
import org.bouncycastle.asn1.ASN1Object
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
//import org.bouncycastle.jce.provider
import org.constellation.crypto.WalletKeyStore
import scala.collection.JavaConverters._
import scala.collection.mutable.ListBuffer
import org.bitcoinj.wallet.{DeterministicKeyChain, DeterministicSeed}


class ASN1ObjectInstance(pKI: PrivateKeyInfo) extends ASN1Object {
  def toASN1Primitive = pKI.parsePrivateKey().toASN1Primitive
  override def getEncoded(str: String): Array[Byte] = super.getEncoded(str)
}

object HdKeys extends App {//todo use for HDwallet exe
  def signWithKeyOfDepth(hDWallet: DeterministicKeyChain, path: ImmutableList[ChildNumber], keyDepth: Int, payload: Array[Byte]) = {
    assert(keyDepth <= 99)//todo make config for key utils
    val pathOfDepth = path.asScala.toList :+ new ChildNumber(44 | ChildNumber.HARDENED_BIT)//(new ChildNumber(44 | ChildNumber.HARDENED_BIT))
    val keyOfDepth = hDWallet.getKeyByPath(pathOfDepth.asJava, true)//new ChildNumber(44 | ChildNumber.HARDENED_BIT)
    val keyOfDepthBytes = keyOfDepth.getPrivKeyBytes
    val privKeyOfDepth: PrivateKey = KeyFactory.getInstance("PKCS12", "BC").generatePrivate(new PKCS8EncodedKeySpec(keyOfDepthBytes))
    val signedPayload: Array[Byte] = signData(payload)(privKeyOfDepth)
    signedPayload
  }

  val (mnemonic, passwordSalt) = args match {
    case Array(m, pw) => (ListBuffer(m.split("-"): _*).asJava, pw)//todo check 12 or 13 provided explicitly?
    case Array(pw) => (ListBuffer(List.empty[String]: _*).asJava, pw)
    case Array() => (ListBuffer(List.empty[String]: _*).asJava, "")
  }
  val dagDir = System.getProperty("user.home") + "/.dag" //todo dry by putting into own into files
  val acctDir = dagDir + "/acct"
  val keyDir = dagDir + "/key"
  //todo need extra dir to correspond to which mnemonic
  //if HD pub key dir not = to all first 100, then replace with first 100
  val loadExistingOrGetNewMnemonic: java.util.List[String] = if (mnemonic.isEmpty) ListBuffer(WalletKeyStore.generateMnemonic.split(" "): _*).asJava else mnemonic
  val seed = MnemonicCode.toSeed(loadExistingOrGetNewMnemonic, passwordSalt)
  val mnemonicSeed = new DeterministicSeed(loadExistingOrGetNewMnemonic, seed, passwordSalt, 10L)
  val (loadedFromSeed: DeterministicKeyChain, dagPath: ImmutableList[ChildNumber]) = WalletKeyStore.seedToKeys(mnemonicSeed)
  assert(loadExistingOrGetNewMnemonic == loadedFromSeed.getMnemonicCode)
}

object GetOrCreateKeys//todo use for one key pair exe
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
  val signature: Array[Byte] = signData(prevTxHash)(privKey)//todo change to payload of prevTxHash and tx content?
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
