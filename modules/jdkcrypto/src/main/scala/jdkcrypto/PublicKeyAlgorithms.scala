package jwt.jdkcrypto

import cats._
import jwt._
import sun.security.rsa.RSAPrivateCrtKeyImpl

import java.security.spec.{PKCS8EncodedKeySpec, RSAPublicKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey, Signature}

trait ECAlgorithms extends AsymmetricKeyAlgorithm {
  def algorithm: String
  def keyfactoryInstance: String
  def keysize: Int
  override def fromJdkSignatureToJws(signature: Array[Byte]): Array[Byte] = utils.ellipticCurve.der2concat(signature, keysize)
  override def fromJwsSignatureToJdk(signature: Array[Byte]): Array[Byte] = {
    utils.ellipticCurve.concat2der(signature) }
}

object AsymmetricKeyAlgorithm {
  def rsa(bitsize: String): AsymmetricKeyAlgorithm = new RsaKeyAlgorithm {
    override def algorithm: String = s"SHA${bitsize}withRSA"
    override def keyfactoryInstance: String = "RSA"
    override def alg: String = s"RS$bitsize"
  }

  def ecdsa(keySize: Int): AsymmetricKeyAlgorithm = new ECAlgorithms {
    override def algorithm: String = s"SHA${bitsize}withECDSA"
    override def keyfactoryInstance: String = "EC"
    override def alg: String = s"EC$bitsize"
    override def keysize = keySize
    private val bitsize = keySize * 8
  }
}

trait RsaKeyAlgorithm extends AsymmetricKeyAlgorithm {
  def generatePublicKey(privateKeyPem: String) = {
    val privateKey = loadPrivateKey(privateKeyPem)
    val keyspec = privateKey.asInstanceOf[RSAPrivateCrtKeyImpl]
    val publicKeyspec = new RSAPublicKeySpec(keyspec.getModulus, keyspec.getPublicExponent)
    val keyfactory = KeyFactory.getInstance(keyfactoryInstance)

    keyfactory.generatePublic(publicKeyspec)
  }
}

trait AsymmetricKeyAlgorithm extends JsonWebAlgorithmInstance { self =>

  def algorithm: String
  def keyfactoryInstance: String

  def fromJdkSignatureToJws(signature: Array[Byte]): Array[Byte] = signature
  def fromJwsSignatureToJdk(signature: Array[Byte]): Array[Byte] = signature

  private def signatureInstance = Signature.getInstance(algorithm)

  def loadPrivateKey(key: String): PrivateKey = {
    val pem = utils.loadPEM(key)
    val keyfactory = KeyFactory.getInstance(keyfactoryInstance)
    val pkcs8 = new PKCS8EncodedKeySpec(pem)
    keyfactory.generatePrivate(pkcs8)
  }

  def loadPublicKey(key: String): PublicKey = {
    val pem = utils.loadPEM(key)
    val keyfactory = KeyFactory.getInstance(keyfactoryInstance)
    val x509 = new X509EncodedKeySpec(pem)
    keyfactory.generatePublic(x509)
  }

  override def issuer[F[_], T](key: String)(implicit ev: Monad[F]): JwtIssuer[F, T] = {
    val privateKey = loadPrivateKey(key)

    new JwtIssuer[F, T] {
      override def alg: String = self.alg
      override def signPayload(payload: String): F[Array[Byte]] = {
        val signature = signatureInstance
        signature.initSign(privateKey)
        signature.update(payload.getBytes)
        Monad[F].pure(fromJdkSignatureToJws(signature.sign()))
      }
    }
  }

  override def validator[F[_], T](key: String)(implicit ev: Monad[F]): JwtValidator[F, T] = {
//    val pem = utils.loadPEM(key)
//    val keyfactory = KeyFactory.getInstance(keyfactoryInstance)
//    val x509 = new X509EncodedKeySpec(pem)
//    val publicKey = keyfactory.generatePublic(x509)

    val publicKey = loadPublicKey(key)

    new JwtValidator[F, T] {
      override def validateM(headers: T, claims: T, token: String): F[ValidationResult] = {
        Monad[F].pure {
          token.split('.').toList match {
            case (h :: c :: t :: Nil) =>
              val signature = signatureInstance
              signature.initVerify(publicKey)
              signature.update(s"$h.$c".getBytes)
              if (signature.verify(fromJwsSignatureToJdk(jwt.utils.b64decode(t)))) ValidToken
              else SignatureNotMatch
            case _ => //false
              NotToken
          }
        }
      }
    }
  }
}
