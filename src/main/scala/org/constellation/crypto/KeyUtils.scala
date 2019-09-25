package org.constellation.crypto

import java.io.{ByteArrayInputStream, FileInputStream}
import java.math.BigInteger
import java.security.cert.CertificateFactory
import java.security.spec.{ECGenParameterSpec, PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, SecureRandom, _}
import java.util.{Base64, Date}

import better.files.File
import com.google.common.hash.Hashing
import com.typesafe.scalalogging.StrictLogging
import org.bouncycastle.jce.provider
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.spongycastle.asn1.x500.style.BCStyle
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo
import org.spongycastle.cert.X509v1CertificateBuilder
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


object WalletKeyStore extends App {
  import java.io.FileOutputStream
  import java.io.File
  import java.security.KeyStore

  val ECDSA = "ECDsA"

  def makeKeyPairFrom(provider: Provider): KeyPair = {
    val keyGen: KeyPairGenerator = KeyPairGenerator.getInstance("ECDsA", provider)
    val ecSpec = new ECGenParameterSpec("secp256k1")
    keyGen.initialize(ecSpec, SecureRandom.getInstance("NativePRNGNonBlocking"))
    keyGen.generateKeyPair
  }

  def loadSecureKeys(password: String = "fakepassword") = {

    val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
    val keyDir = dagDir + "/encrypted_key"
    val p12File = better.files.File(keyDir + "keystoretest.p12").toJava
    val bksFile = better.files.File(keyDir + "keystoretest.bks").toJava

    val p12 = KeyStore.getInstance("PKCS12", "BC")
    p12.load(new java.io.FileInputStream(p12File), password.toCharArray)

    val bks: KeyStore = KeyStore.getInstance("BKS", "BC")
    bks.load(new FileInputStream(bksFile), password.toCharArray)

    val privKey: PrivateKey = bks.getKey("test_rsa", password.toCharArray).asInstanceOf[PrivateKey]
    val pubKey: PublicKey = p12.getCertificate("test_cert").getPublicKey
    (privKey, pubKey)
  }

  def testGetKeys(password: String = "fakepassword") = {
    import java.security.Security
    Security.addProvider(new BouncyCastleProvider)
    val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
    val keyDir = dagDir + "/encrypted_key"
    val p12File = better.files.File(keyDir + "/keystoretest.p12").toJava
    val bksFile = better.files.File(keyDir + "/keystoretest.bks").toJava
    val pass = password.toCharArray
//    val (p12A, bksA) = WalletKeyStore.makeWalletKeyStore(
//      saveCertTo = Some(p12File),
//      savePairsTo = Some(bksFile),
//      password = pass,
//      numECDSAKeys = 10
//    )

    println("testGetKeys" + "\n")

    val p12 = KeyStore.getInstance("PKCS12", "BC")
    p12.load(new java.io.FileInputStream(p12File), pass)

    val bks: KeyStore = KeyStore.getInstance("BKS", "BC")
    bks.load(new FileInputStream(bksFile), pass)

    val protParam = new KeyStore.PasswordProtection(pass)

//    assert(p12A.getCertificate("test_cert") == p12.getCertificate("test_cert"))
    val privKey: Key = bks.getKey("test_rsa", pass)
//    assert(privKey.isInstanceOf[PrivateKey])
    val publicKey: PublicKey = p12.getCertificate("test_cert").getPublicKey
//    assert(publicKey.isInstanceOf[PublicKey])
    (privKey.asInstanceOf[PrivateKey], publicKey)
  }

  def makeWalletKeyStore(
                          password: Array[Char],
                          saveCertTo: Option[File] = None,
                          savePairsTo: Option[File] = None,
                          validityInDays: Int = 500000,
                          orgName: String = "test",
                          orgUnitName: String = "test",
                          localityName: String = "test",
                          numECDSAKeys: Int = 1,
                          certEntryName: String = "test_cert",
                          rsaEntryName: String = "test_rsa",
                          ecdsaEntryNamePrefix: String = "ecdsa",
                          sslKeySize: Int = 4096
                        ): (KeyStore, KeyStore) = {
    import java.security.Security
    // Note this requires JDK 8u151 +
    // https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
    Security.setProperty("crypto.policy", "unlimited")
    // java.lang.SecurityException: JCE cannot authenticate the provider SC
    // Use BC for now, for some reason SC not working. Just google it theres a fix.
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
    val v1CertGen = new X509v1CertificateBuilder(x500Name, BigInteger.valueOf(random.nextLong()),startDate,endDate,x500Name,subjectPublicKeyInfo)//(x500Name, BigInteger.valueOf(random.nextLong()), startDate, endDate)//
    //(X500Name issuer, BigInteger serial, Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo)

    val sigGen = new JcaContentSignerBuilder("SHA512withECDSA")
      .setProvider(getProv).build(keyPair.getPrivate)//todo test prov -> insertProvider in .setProvider

    val x509CertificateHolder = v1CertGen.build(sigGen)

    val certf = CertificateFactory.getInstance("X.509")
    val cert = certf.generateCertificate(new ByteArrayInputStream(x509CertificateHolder.getEncoded))

    // There's another solution here: https://stackoverflow.com/questions/13894699/java-how-to-store-a-key-in-keystore
    // Maybe worth looking at we'll see. This works for now.
    // Theres a lot of different keystores we actually need to support.
    // PKCS12 for the SSL certs (between nodes unless they get a proper cert from lets encrypt) is easy
    // BKS is also easy
    // There's a lot more and more details to get into. This is pretty complicated but this can serve
    // As an initial example to at least get the right classes in place.
    val ks: KeyStore = KeyStore.getInstance("PKCS12", bcProvider)
    ks.load(null, password)
    // https://stackoverflow.com/questions/6656263/why-do-i-get-the-error-cannot-store-non-privatekeys-when-creating-an-ssl-socke
    // ^ in case next step is confusing:

    import java.io.FileOutputStream
    import java.security.KeyStore
    val bks = KeyStore.getInstance("BKS", "BC")
    bks.load(null, null)

    ks.setCertificateEntry(certEntryName, cert)
    ks.setKeyEntry(rsaEntryName, keyPair.getPrivate, password, Array(cert))

    val ecdsaKeys = Seq.fill(numECDSAKeys){makeKeyPairFrom(provider = prov)}

    ecdsaKeys.zipWithIndex.foreach{
      case (k, i) =>
        bks.setCertificateEntry(certEntryName, cert)
        bks.setKeyEntry(rsaEntryName, keyPair.getPrivate, password, Array(cert))
        bks.setKeyEntry(s"${ecdsaEntryNamePrefix}_priv_" + i, k.getPrivate, password, Array(cert))
        bks.setKeyEntry(s"${ecdsaEntryNamePrefix}_pub_" + i, k.getPublic, password, Array(cert))
    }
    savePairsTo.foreach { file =>
      bks.store(new FileOutputStream(file), password)
    }

    saveCertTo.foreach { file =>
      ks.store(new FileOutputStream(file), password)
    }

    ks -> bks
  }

//  def apply(args: Array[String]) = {
//    val password: Array[Char] = args(0).toCharArray
//    val saveCertTo: File = File(args(1)).toJava
//    val savePairsTo: File = File(args(2)).toJava
//    makeWalletKeyStore(password, Some(saveCertTo), Some(savePairsTo))
    val dagDir = System.getProperty("user.home") +"/.dag"//todo dry by putting into own into files
    val certFile = better.files.File(dagDir + "/cert")
    val encKs = better.files.File(dagDir + "/encrypted_keystore")
    makeWalletKeyStore("password".toCharArray, Some(certFile.toJava), Some(encKs.toJava))
//  }

}


