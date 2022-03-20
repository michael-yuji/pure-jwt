
import cats.Monad
import cats.data.EitherT

package object jwt
{
  sealed trait ValidationResult
  case object ValidToken extends ValidationResult
  case object SignatureNotMatch extends ValidationResult
  case object NotToken extends ValidationResult
  case class DecodeFailure[T](value: T) extends ValidationResult
  case class InvalidToken[T](value: T) extends ValidationResult

  object Converter {
    def identityConverter[F[_], A](implicit ev: Monad[F]): Converter[F, A, A] = a => EitherT.fromEither(Right(a))
  }

  trait Converter[F[_], A, B] {
    def convert(f: A): EitherT[F, DecodeFailure[_], B]
    def mapM[C](f: B => EitherT[F, DecodeFailure[_], C])(implicit ev: Monad[F]): Converter[F, A, C] = { a =>
      convert(a).flatMap(b => f(b))
    }

    def map[C](f: B => C)(implicit ev: Monad[F]): Converter[F, A, C] = a => convert(a).map(f)
  }

  case class JsonWebToken[T](header: T, claims: T, token: String)

  object JwtDecoder {
    def apply[F[_], T](validators: JwtValidator[F, T])(implicit ev: Monad[F]): JwtDecoder[F, T, JsonWebToken[T]] =
      new JwtDecoder(validators, Converter.identityConverter[F, JsonWebToken[T]])
  }

  class JwtDecoder[F[_], T, A](validators: JwtValidator[F, T], converter: Converter[F, JsonWebToken[T], A]) {

    def map[B](f: A => B)(implicit ev: Monad[F]): JwtDecoder[F, T, B] = new JwtDecoder(validators, converter.map(f))

    def mapEither[E, B](f: A => Either[E, B])(implicit ev: Monad[F]): JwtDecoder[F, T, B] =
      new JwtDecoder(validators,
        converter.mapM(a => EitherT.fromEither(f(a).left.map(DecodeFailure(_)))))

    def tryMap[B](f: A => B)(implicit ev: Monad[F]): JwtDecoder[F, T, B] =
      mapEither { a => scala.util.Try(f(a)).toEither.left.map(DecodeFailure(_)) }


    //      new JwtDecoder(validators, converter.map(a => scala.util.Try(f(a)).toEither.left.map(DecodeFailure(_))))

    def validate(token: String)(implicit ev: Monad[F], driver: JsonDriver[T])//: EitherT[F, ValidationResult, A] =
      : F[Either[ValidationResult, A]] =
    {
      token.split('.').toList match {
        case (header :: claim :: _ :: Nil) =>

//          val t = EitherT.fromEither(Left(NotToken).asInstanceOf[Either[ValidationResult, A]])

          val decodedResult = (for {
            headerValue <- driver.parse(utils.b64decodeToString(header))
            claimsValue <- driver.parse(utils.b64decodeToString(claim))

            result = ev.flatMap (validators.validateM(headerValue, claimsValue, token)) {
              case ValidToken =>
                val t = converter.convert(JsonWebToken(headerValue, claimsValue, token)).value.asInstanceOf[F[Either[ValidationResult, A]]]

                t
              case otherwise =>
                val t = EitherT.fromEither(Left(otherwise).asInstanceOf[Either[ValidationResult, A]]).value
                t
            }

          } yield result)//.getOrElse(EitherT.fromEither(Left(NotToken).asInstanceOf[Either[ValidationResult, A]]))//result.getOrElse(EitherT.fromEither(Left(NotToken).asInstanceOf[Either[ValidationResult, A]])).value

        decodedResult.getOrElse(ev.pure(Left(NotToken)))
        case _ =>
          EitherT.fromEither(Left(NotToken).asInstanceOf[Either[ValidationResult, A]]).value
      }
    }
  }

  trait JsonDriver[JsonValue] {
    def write(value: JsonValue): String
    def parse(source: String): Option[JsonValue]
    def stringValue(value: String): JsonValue
    def jsonGetLong(value: JsonValue): Option[Long]
    def jsonGetString(value: JsonValue): Option[String]
    def jsonGetBool(value: JsonValue): Option[Boolean]
    def jsonGetArray(value: JsonValue): Option[List[JsonValue]]
    def getKeyed(obj: JsonValue, key: String): Option[JsonValue]
  }

  trait JsonWebAlgorithmInstance {
    def alg: String
    def issuer[F[_], T](key: String)(implicit ev: Monad[F]): JwtIssuer[F, T]
    def validator[F[_], T](key: String)(implicit ev: Monad[F]): JwtValidator[F, T]
  }

  case class ClaimValidationFailure(claim: String)
}
