package org.constellation.crypto

import java.io.{ByteArrayInputStream, FileInputStream, FileWriter}
import java.math.BigInteger
import java.security.cert.{Certificate, CertificateFactory, X509CertSelector}
import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, SecureRandom, _}
import java.util.{Base64, Date}

import better.files.File
import com.github.alanverbner.bip39
import com.google.common.collect.ImmutableList
import com.google.common.hash.Hashing
import com.typesafe.scalalogging.StrictLogging
import org.bitcoinj.core.{NetworkParameters, Sha256Hash}
import org.bitcoinj.crypto.{ChildNumber, KeyCrypter}
import org.bitcoinj.params.MainNetParams
import org.bitcoinj.script.Script
import org.bitcoinj.wallet.{DeterministicKeyChain, DeterministicSeed}
import org.bouncycastle.jce.provider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.spongycastle.asn1.x500.style.BCStyle
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.cert.X509v1CertificateBuilder
import org.spongycastle.openssl.PEMWriter
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder

/**
  * Need to compare this to:
  * https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/core/ECKey.java
  *
  * The implementation here is a lot simpler and from stackoverflow post linked below
  * but has differences. Same library dependency but needs to be checked
  *
  * BitcoinJ is stuck on Java 6 for some things, so if we use it, probably better to pull
  * out any relevant code rather than using as a dependency.
  *
  * Based on: http://www.bouncycastle.org/wiki/display/JA1/Elliptic+Curve+Key+Pair+Generation+and+Key+Factories
  * I think most of the BitcoinJ extra code is just overhead for customization.
  * Look at the `From Named Curves` section of above citation. Pretty consistent with stackoverflow code
  * and below implementation.
  *
  * Need to review: http://www.bouncycastle.org/wiki/display/JA1/Using+the+Bouncy+Castle+Provider%27s+ImplicitlyCA+Facility
  * for security policy implications.
  *
  */
object KeyUtils extends StrictLogging {

  def insertProvider(): BouncyCastleProvider = {
    import java.security.Security

    val provider = new BouncyCastleProvider
    val ret = Security.insertProviderAt(provider, 1)
    logger.debug(s"Insert provider return $ret")
    provider
  }

  val provider: BouncyCastleProvider = insertProvider()

  private val ECDSA = "ECDsA"
  private val secureRandom: SecureRandom = SecureRandom.getInstance("NativePRNGNonBlocking")
  private val secp256k = "secp256k1"
  private val DefaultSignFunc = "SHA512withECDSA"
  private val PublicKeyHexPrefix: String = "3056301006072a8648ce3d020106052b8104000a03420004"
  private val PublicKeyHexPrefixLength: Int = PublicKeyHexPrefix.length
  private val PrivateKeyHexPrefix: String =
    "30818d020100301006072a8648ce3d020106052b8104000a047630740201010420"
  private val PrivateKeyHexPrefixLength: Int = PrivateKeyHexPrefix.length

  /**
    * Simple Bitcoin like wallet grabbed from some stackoverflow post
    * Mostly for testing purposes, feel free to improve.
    * Source: https://stackoverflow.com/questions/29778852/how-to-create-ecdsa-keypair-256bit-for-bitcoin-curve-secp256k1-using-spongy
    * @return : Private / Public keys following BTC implementation
    */
  def makeKeyPair(): KeyPair = {
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance(ECDSA, provider)
    val ecSpec = new ECGenParameterSpec(secp256k)
    keyGen.initialize(ecSpec, secureRandom)
    keyGen.generateKeyPair
  }

  // Utilities for getting around conversion errors / passing around parameters
  // through strange APIs that might take issue with your strings

  def base64(bytes: Array[Byte]): String = Base64.getEncoder.encodeToString(bytes)

  def fromBase64(b64Str: String): Array[Byte] = Base64.getDecoder.decode(b64Str)

  def base64FromBytes(bytes: Array[Byte]): String = new String(bytes)

  /**
    * https://stackoverflow.com/questions/31485517/verify-ecdsa-signature-using-spongycastle
    * https://docs.oracle.com/javase/7/docs/technotes/guides/security/SunProviders.html
    * https://bouncycastle.org/specifications.html
    * https://stackoverflow.com/questions/16662408/correct-way-to-sign-and-verify-signature-using-bouncycastle
    * @param bytes: Data to sign. Use text.toBytes or even better base64 encryption
    * @param signFunc: How to sign the data. There's a bunch of these,
    *                this needs to be made into an enum or something (instead of a val const),
    *                make sure if you fix it you make it consistent with json4s
    *                usages!
    * @param privKey: Java Private Key generated above with ECDSA
    * @return : Signature of bytes based on the text signed with the private key
    *         This can be checked by anyone to be equal to the input text with
    *         access only to the public key paired to the input private key! Fun
    */
  def signData(
    bytes: Array[Byte],
    signFunc: String = DefaultSignFunc
  )(implicit privKey: PrivateKey): Array[Byte] = {
    val signature = Signature.getInstance(signFunc, provider)
    signature.initSign(privKey, secureRandom)
    signature.update(bytes)
    val signedOutput = signature.sign()
    signedOutput
  }

  /**
    * Verify a signature of some input text with a public key
    * This is called by verifier nodes checking to see if transactions are legit
    *
    * WARNING IF THIS FUNCTION IS MODIFIED BY AN ILLEGITIMATE NODE YOU WILL
    * BE BLACKLISTED FROM THE NETWORK. DO NOT MODIFY THIS FUNCTION UNLESS YOU
    * HAVE APPROVAL. OTHER NODES WILL CHECK YOUR VERIFICATIONS.
    *
    * YOU HAVE BEEN WARNED.
    *
    * @param originalInput: Byte input to verify, recommended that you
    *                         use base64 encoding if dealing with arbitrary text
    *                         meant to be shared over RPC / API protocols that
    *                         have issues with strange characters. If within same
    *                         JVM then just use text.getBytes (see unit tests for examples)
    * @param signedOutput: Byte array of output of calling signData method above
    * @param signFunc: Signature function to use. Use the default one for now.
    *                To be discussed elsewhere if revision necessary
    * @param pubKey: Public key to perform verification against.
    *              Only the public key which corresponds to the private key who
    *              performed the signing will verify properly
    * @return : True if the signature / transaction is legitimate.
    *         False means dishonest signer / fake transaction
    */
  def verifySignature(
    originalInput: Array[Byte],
    signedOutput: Array[Byte],
    signFunc: String = DefaultSignFunc
  )(implicit pubKey: PublicKey): Boolean = {
    val verifyingSignature = Signature.getInstance(signFunc, provider)
    verifyingSignature.initVerify(pubKey)
    verifyingSignature.update(originalInput)
    val result = verifyingSignature.verify(signedOutput)
    result
  }

  // https://stackoverflow.com/questions/42651856/how-to-decode-rsa-public-keyin-java-from-a-text-view-in-android-studio

  def bytesToPublicKey(encodedBytes: Array[Byte]): PublicKey = {
    val spec = new X509EncodedKeySpec(encodedBytes)
    val kf = KeyFactory.getInstance(ECDSA, provider)
    kf.generatePublic(spec)
  }

  def bytesToPrivateKey(encodedBytes: Array[Byte]): PrivateKey = {
    val spec = new PKCS8EncodedKeySpec(encodedBytes)
    val kf = KeyFactory.getInstance(ECDSA, provider)
    kf.generatePrivate(spec)
  }

  def hex2bytes(hex: String): Array[Byte] =
    if (hex.contains(" ")) {
      hex.split(" ").map(Integer.parseInt(_, 16).toByte)
    } else if (hex.contains("-")) {
      hex.split("-").map(Integer.parseInt(_, 16).toByte)
    } else {
      hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
    }

  def bytes2hex(bytes: Array[Byte], sep: Option[String] = None): String =
    sep match {
      case None => bytes.map("%02x".format(_)).mkString
      case _    => bytes.map("%02x".format(_)).mkString(sep.get)
    }

  def publicKeyToHex(publicKey: PublicKey): String = {
    val hex = bytes2hex(publicKey.getEncoded)
    hex.slice(PublicKeyHexPrefixLength, hex.length)
  }

  def hexToPublicKey(hex: String): PublicKey =
    bytesToPublicKey(hex2bytes(PublicKeyHexPrefix + hex))

  def privateKeyToHex(privateKey: PrivateKey): String = {
    val hex = bytes2hex(privateKey.getEncoded)
    hex.slice(PrivateKeyHexPrefixLength, hex.length)
  }

  def hexToPrivateKey(hex: String): PrivateKey =
    bytesToPrivateKey(hex2bytes(PrivateKeyHexPrefix + hex))

  // convert normal string to hex bytes string

  def string2hex(str: String): String =
    str.toList.map(_.toInt.toHexString).mkString

  // convert hex bytes string to normal string

  def hex2string(hex: String): String =
    hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toChar).mkString

  def keyHashToAddress(hash: String): String = {
    val end = hash.slice(hash.length - 36, hash.length)
    val validInt = end.filter { Character.isDigit }
    val ints = validInt.map { _.toString.toInt }
    val sum = ints.sum
    val par = sum % 9
    val res2 = "DAG" + par + end
    res2
  }

  // TODO : Use a more secure address function.
  // Couldn't find a quick dependency for this, TBI
  // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses

  def publicKeyToAddressString(
    key: PublicKey
  ): String = {
    val keyHash = Base58.encode(Hashing.sha256().hashBytes(key.getEncoded).asBytes())
    keyHashToAddress(keyHash)
  }

  // TODO: Update to use encrypted wallet see below
  def loadDefaultKeyPair(keyPath: String = ".dag/key"): KeyPair = {
    import constellation._
    val keyPairFile = File(keyPath)
    val keyPair: KeyPair =
      if (keyPairFile.notExists) {
        logger.warn(
          s"Key pair not found in $keyPairFile - Generating new key pair"
        )
        val kp = makeKeyPair()
        keyPairFile.write(kp.json)
        kp
      } else {
        try {
          keyPairFile.lines.mkString.x[KeyPair]
        } catch {
          case e: Exception =>
            logger.error(
              s"Keypair stored in $keyPairFile is invalid. Please delete it and rerun to create a new one.",
              e
            )
            throw e
        }
      }
    keyPair
  }

}

import javax.annotation.Nullable
class BIP44 extends DeterministicKeyChain{
  override def DeterministicKeyChain(seed: DeterministicSeed,
                                     @Nullable crypter: KeyCrypter,
                                     outputScriptType: Script.ScriptType,
                                     accountPath: ImmutableList[ChildNumber]) = {

  }
}

object WalletKeyStore extends App {
  import java.io.File
  import java.security.KeyStore
  import java.io.FileOutputStream
  import com.github.alanverbner.bip39.{EnglishWordList, Entropy128, WordList}
  import org.spongycastle.util.encoders.Hex



  val ECDSA = "ECDsA"

  def seedToKeys()= {
    import com.sun.tools.javac.util.Convert
    val recoveryPhrase = generateMnemonic
//      "heavy virus hollow shrug shadow double dwarf affair novel weird image prize frame anxiety wait"
//    val nxtPrivateKey = Hex.decode("200a8ead018adb6c78f2c821500ad13f5f24d101ed8431adcfb315ca58468553")
//    val nxtPublicKey = Hex.decode("163c6583ed489414f27e73a74f72080b478a55dfce4a086ded2990976e8bb81e")
//    val nxtRsAddress = "NXT-CGNQ-8WBM-3P2F-AVH9J"
//    val nxtAccountId = Convert.parseAccountId(NxtMain.get, "9808271777446836886")

    val recipient = "NXT-RZ9H-H2XD-WTR3-B4WN2"
//    val recipientPublicKey = Convert.parseHexString("8381e8668479d27316dced97429c2bf7fde9d909cce2c53d565a4078ee82b13a")
    import org.bitcoinj.crypto.DeterministicHierarchy
    import org.bitcoinj.crypto.HDKeyDerivation
    import org.bitcoinj.wallet._
//    import org.bitcoinj.wallet.DeterministicSeed
    import org.bitcoinj.wallet.KeyChain.KeyPurpose
    import org.spongycastle.crypto.params.KeyParameter
//    val aesKey: org.spongycastle.crypto.params.KeyParameter = new KeyParameter()
    // m/44'/0'/0'/0/4// m/44'/0'/0'/0/4

    import org.bitcoinj.core.Sha256Hash
    val networkParams = NetworkParameters.ID_MAINNET//todo ensure compatability
    val EXPECTED_ADDRESS_4: String ="18dxk72otf2amyAsjiKnEWhox5CJGQHYGA" //todo make EXPECTED_ADDRESS for $dag
    val secs = 1389353062L// random seed
    val ENTROPY: Array[Byte] = Sha256Hash.hash("don't use a string seed like this in real life".getBytes())
    val seed = new DeterministicSeed(ENTROPY, "", secs)
    import com.google.common.collect.ImmutableList
    import org.bitcoinj.crypto.ChildNumber
    import org.bitcoinj.crypto.DeterministicHierarchy
    import org.bitcoinj.crypto.HDKeyDerivation
//    import org.bitcoinj.wallet.DeterministicKeyChain
    import org.bitcoinj.wallet.DeterministicSeed
//    val seed = new DeterministicSeed(TREZOR_SEED_PHRASE, null, "", secs)
    val privateMasterKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes)
    println("privateMasterKey = " + privateMasterKey)

    val key_m_44h = HDKeyDerivation.deriveChildKey(privateMasterKey, new ChildNumber(44 | ChildNumber.HARDENED_BIT))
    println("key_m_44h deterministic key = " + key_m_44h)

    val key_m_44h_0h = HDKeyDerivation.deriveChildKey(key_m_44h, ChildNumber.ZERO_HARDENED)
    println("key_m_44h_0h deterministic key = " + key_m_44h_0h)

    val deterministicHierarchy = new DeterministicHierarchy(key_m_44h_0h)

    val key_m_44h_0h_0h = deterministicHierarchy.deriveChild(key_m_44h_0h.getPath, false, false, new ChildNumber(0, true))
    println("key_m_44h_0h_0h = " + key_m_44h_0h_0h)

    val key_m_44h_0h_0h_path: ImmutableList[ChildNumber] = key_m_44h_0h_0h.getPath
    println("key_m_44h_0h_0h_path = " + key_m_44h_0h_0h_path)

    // Generate a chain using the derived key i.e. master private key is available
    val accountChainBuilder = DeterministicKeyChain.builder()
    accountChainBuilder.passphrase("password")
    accountChainBuilder.random(new SecureRandom())
    accountChainBuilder.accountPath(key_m_44h_0h_0h_path)
    accountChainBuilder.seed(seed)

      //(seed, null, Script.ScriptType.P2PKH, key_m_44h_0h_0h_path)
    val accountChain = accountChainBuilder.build()
//    println("accountChain = " + accountChain)
//    val testKey = HDKeyDerivation.createMasterPrivateKey(seed2.getSeedBytes)
//    val bip44chain = new DeterministicKeyChain(testKey, false,
//      Script.ScriptType.P2PKH,
//      ImmutableList.of(new ChildNumber(44, true),
//        new ChildNumber(1, true),
//        new ChildNumber(0, true))
//    )
//
//
//    val seed = new DeterministicSeed(recoveryPhrase, null, "", 0)
//    val params = MainNetParams.get()
////    val wallet = Wallet.fromSeedeed(params, seed)
//    val masterKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes)
//    val hierarchy = new DeterministicHierarchy(masterKey)
//    import org.bitcoinj.crypto.DeterministicKey
//    import org.bitcoinj.crypto.HDKeyDerivation
//    val rootKey: DeterministicKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes)
//    rootKey.setCreationTimeSeconds(seed.getCreationTimeSeconds)
//    rootKey.getChildNumber()
  }

  def generateMnemonic = {
    val engWordLst = WordList.load(EnglishWordList).get
    val sentence = bip39.generate(Entropy128, WordList.load(EnglishWordList).get, new SecureRandom())
    println(sentence)
    assert(bip39.check(sentence, engWordLst))
    sentence
  }

  def makeKeyPairFrom(provider: Provider): KeyPair = {
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("ECDsA", provider)
    val ecSpec = new ECGenParameterSpec("secp256k1")
    keyGen.initialize(ecSpec, SecureRandom.getInstance("NativePRNGNonBlocking"))
    keyGen.generateKeyPair
  }

  def loadOrGetKeys(password: String = "fakepassword") = {
    import java.security.Security
    Security.addProvider(new BouncyCastleProvider)

    val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
    val keyDir = dagDir + "/encrypted_key"
    val keyStoreFile = better.files.File(keyDir + "/keystore.p12").toJava
    val pubDir = keyDir + "/pub.pem"
    val pubFile = better.files.File(pubDir).toJava
    val pass = password.toCharArray

    if (!keyStoreFile.exists() | !pubFile.exists()) {
      better.files.File(keyDir).createDirectory()
      keyStoreFile.createNewFile()
      pubFile.createNewFile()
      val p12A = makeWalletKeyStore(pass, Some(keyStoreFile), Some(pubDir))//todo stick to PKCS12 its language agnostic
      val pub = p12A.getCertificate("test_cert").getPublicKey
      val priv = p12A.getKey("test_rsa", pass).asInstanceOf[PrivateKey]
      (priv, pub)
    } else {
      val p12 = KeyStore.getInstance("PKCS12", "BC")
      p12.load(new java.io.FileInputStream(keyStoreFile), pass)

      val publicKey: PublicKey = p12.getCertificate("test_cert").getPublicKey
      val privKey = p12.getKey("test_rsa", pass).asInstanceOf[PrivateKey]
//          assert(publicKey.isInstanceOf[PublicKey])//todo move to test
//          assert(privKey.isInstanceOf[PrivateKey])// todo move to test
      val selector = new X509CertSelector()
      selector.setSubjectPublicKey(publicKey)
      val result = selector.`match`(p12.getCertificate("test_cert"))
//      assert(result)// todo move to test
//      saveCertAsPem(p12.getCertificate("test_cert"), s"/Users/wyatt/.dag/pub.pem")
      (privKey.asInstanceOf[PrivateKey], publicKey)
    }
  }

  def saveCertAsPem(cert: Certificate, outFile: String) = {
    val fileWriter = new FileWriter(outFile)
    val pemWriter = new PEMWriter(fileWriter)
    pemWriter.writeObject(cert.getPublicKey())
    pemWriter.close()
  }

  def makeWalletKeyStore(
                          password: Array[Char],
                          saveKSTo: Option[File] = None,
                          savePubCertTo: Option[String] = None,
                          validityInDays: Int = 500000,
                          orgName: String = "test",
                          orgUnitName: String = "test",
                          localityName: String = "test",
                          numECDSAKeys: Int = 1,
                          certEntryName: String = "test_cert",
                          rsaEntryName: String = "test_rsa",
                          ecdsaEntryNamePrefix: String = "ecdsa",
                          sslKeySize: Int = 4096
                        ): KeyStore = {
    import java.security.Security
    // Note this requires JDK 8u151 +
    // https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
    Security.setProperty("crypto.policy", "unlimited")

    val bcProvider: provider.BouncyCastleProvider = new org.bouncycastle.jce.provider.BouncyCastleProvider()
    val getProv = KeyUtils.insertProvider()
    val prov = bcProvider // makeProvider
    Security.insertProviderAt(prov, 1)
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("EC", getProv)
    keyGen.initialize(256)
    val keyPair = KeyUtils.makeKeyPair//keyGen.generateKeyPair//todo use KeyUtils.makeKeyPair here?
    val startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000)
    val endDate = new Date(System.currentTimeMillis() + validityInDays * 24 * 60 * 60 * 1000)

    val nameBuilder = new X500NameBuilder(BCStyle.INSTANCE)
    nameBuilder.addRDN(BCStyle.O,orgName)
    nameBuilder.addRDN(BCStyle.OU,orgUnitName)
    nameBuilder.addRDN(BCStyle.L,localityName)

    val x500Name: X500Name = nameBuilder.build()
    val random = new SecureRandom()

    val subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic.getEncoded)
    val v1CertGen = new X509v1CertificateBuilder(x500Name, BigInteger.valueOf(random.nextLong()),startDate,endDate,x500Name,subjectPublicKeyInfo)
    val sigGen = new JcaContentSignerBuilder("SHA512withECDSA")
      .setProvider(getProv).build(keyPair.getPrivate)//todo test prov -> insertProvider in .setProvider
    val x509CertificateHolder = v1CertGen.build(sigGen)
    val certf = CertificateFactory.getInstance("X.509")
    val cert = certf.generateCertificate(new ByteArrayInputStream(x509CertificateHolder.getEncoded))
    val ks: KeyStore = KeyStore.getInstance("PKCS12", bcProvider)

    ks.load(null, password)
    ks.setCertificateEntry(certEntryName, cert)
    ks.setKeyEntry(rsaEntryName, keyPair.getPrivate, password, Array(cert))

    saveCertAsPem(ks.getCertificate("test_cert"), savePubCertTo.get)
    ks.store(new FileOutputStream(saveKSTo.get), password)

    ks
  }
  seedToKeys()
}
