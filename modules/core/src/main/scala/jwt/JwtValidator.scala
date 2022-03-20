package jwt

import cats.Monad

import scala.annotation.tailrec

object JwtValidator {
  def fromPure[F[_], T](validation: (T, T, String) => ValidationResult)(implicit ev: Monad[F]): JwtValidator[F, T] =
    (header, claim, sig) => ev.pure(validation(header, claim, sig))
}

trait JwtValidator[F[_], T] { self =>

  def validateM(headers: T, claims: T, token: String): F[ValidationResult]

  def decoder(implicit ev: Monad[F]) : JwtDecoder[F, T, JsonWebToken[T]] = JwtDecoder(this)

  def validate(token: String)(implicit ev: Monad[F], driver: JsonDriver[T]): F[ValidationResult] = {
    token.split('.').toList match {
      case (header :: claim :: _ :: Nil) =>
        (for {
          headerValue <- driver.parse(utils.b64decodeToString(header))
          claimsValue <- driver.parse(utils.b64decodeToString(claim))
        } yield validateM(headerValue, claimsValue, token)).getOrElse(ev.pure(NotToken))
      case _ => Monad[F].pure(NotToken)
    }
  }

  // allow override so some effect framework can implement more efficient `all`
  def all(validators: List[JwtValidator[F, T]])(implicit ev: Monad[F]) = _all(validators)

  def all(validators: JwtValidator[F, T]*)(implicit ev: Monad[F]) = _all(validators.toList)

  @tailrec
  private def _all(validators: List[JwtValidator[F, T]])(implicit ev: Monad[F]): JwtValidator[F, T] =
    validators match {
      case Nil =>
        self
      case header :: Nil =>
        self.and(header)
      case header :: tail =>
        val partial = self.and(header)
        partial._all(tail)
    }

  // allow override so some effect framework can implement more efficient `any`
  def any(validators: List[JwtValidator[F, T]])(implicit ev: Monad[F]) = _any(validators)

  def any(validators: JwtValidator[F, T]*)(implicit ev: Monad[F]) = _any(validators.toList)

  @tailrec
  private def _any(validators: List[JwtValidator[F, T]])(implicit ev: Monad[F]): JwtValidator[F, T] =
    validators match {
      case Nil =>
        self
      case head :: tail =>
        val partial = self.or(head)
        partial._any(tail)
      case head :: Nil =>
        self.or(head)
    }

  def and(next: JwtValidator[F, T])(implicit ev: Monad[F])
  : JwtValidator[F, T] =
    (header, claims, token) => {
      ev.flatMap(self.validateM(header, claims, token)) {
        case ValidToken => next.validateM(header, claims, token)
        case otherwise => ev.pure(otherwise)
      }
    }

  def or(next: JwtValidator[F, T])(implicit ev: Monad[F])
  : JwtValidator[F, T] = (header, claims, token) => {
    ev.flatMap(self.validateM(header, claims, token)) {
      case ValidToken  => Monad[F].pure(ValidToken)
      case _ => next.validateM(header, claims, token)
    }
  }
}