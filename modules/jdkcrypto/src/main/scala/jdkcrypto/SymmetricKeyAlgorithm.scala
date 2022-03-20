package jwt.jdkcrypto

import cats.Monad
import jwt._

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object SymmetricKeyAlgorithm {
  def hs(size: String): SymmetricKeyAlgorithm = new SymmetricKeyAlgorithm {
    override def algorithm: String = s"HmacSHA$size"
    override def alg: String = s"HS$size"
  }
}

trait SymmetricKeyAlgorithm extends JsonWebAlgorithmInstance { self =>
  def algorithm: String
  def signatureInstance = Mac.getInstance(algorithm)

  override def issuer[F[_], T](key: String)(implicit ev: Monad[F])
    : jwt.JwtIssuer[F, T] = new jwt.JwtIssuer[F, T]
  {
    def alg = self.alg
    override def signPayload(payload: String): F[Array[Byte]] = {
      Monad[F].pure {
        val spec = new SecretKeySpec(key.getBytes, alg)
        val signature = signatureInstance
        signature.init(spec)
        signature.doFinal(payload.getBytes)
      }
    }
  }

  override def validator[F[_], T](key: String)(implicit ev: Monad[F]): jwt.JwtValidator[F, T] =
    (_, _, token) => {
      Monad[F].pure {
        token.split('.').toList match {
          case (h :: c :: t :: Nil) =>
            val signature = signatureInstance
            val spec = new SecretKeySpec(key.getBytes, alg)
            signature.init(spec)
            if (jwt.utils.b64encodeBytes(signature.doFinal(s"$h.$c".getBytes)) == t)
              ValidToken
            else
              SignatureNotMatch
          case _ =>
            NotToken
        }
    }
  }
}