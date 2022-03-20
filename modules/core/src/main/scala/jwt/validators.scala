package jwt

import cats.Monad

object validators
{
  private def failedClaim(claim: String): ValidationResult = InvalidToken(ClaimValidationFailure(claim))

  private def assertClaim(cond: => Boolean): Option[ValidationResult] = if (cond) Some(ValidToken) else None

  def validateNbf[F[_], T](timeSource: => Long)(implicit
    driver: JsonDriver[T],
    m: Monad[F]
  ): JwtValidator[F, T] = (_, claims, _) => {
    Monad[F].pure {
      (for {
        nbf <- driver.getKeyed(claims, "nbf")
        value <- driver.jsonGetLong(nbf)
        result <- assertClaim(value >= timeSource)
      } yield result).getOrElse(failedClaim("nbf"))
    }
  }

  def validateExp[F[_], T](timeNow: => Long)(implicit
    driver: JsonDriver[T],
    m: Monad[F]
  ): JwtValidator[F, T] = (_, claims, _) => {
    Monad[F].pure {
      (for {
        exp <- driver.getKeyed(claims, "exp")
        value <- driver.jsonGetLong(exp)
        result <- assertClaim(value <= timeNow)
      } yield result).getOrElse(failedClaim("exp"))
    }
  }

  def validateIssusers[F[_], T](validIssuers: => List[String])(implicit
    driver: JsonDriver[T], m: Monad[F]): JwtValidator[F, T] = (_, claims, _) =>
  {
    Monad[F].pure {
      (for {
        iss <- driver.getKeyed(claims, "iss")
        value <- driver.jsonGetString(iss)
        result <- assertClaim(validIssuers.contains(value))
      } yield result).getOrElse(failedClaim("iss"))
    }
  }
  def validateSubjects[F[_], T](validSubjects: => List[String])(implicit
    driver: JsonDriver[T], m: Monad[F]): JwtValidator[F, T] = (_, claims, _) =>
  {
    Monad[F].pure {
      (for {
        sub <- driver.getKeyed(claims, "sub")
        value <- driver.jsonGetString(sub)
        result <- assertClaim(validSubjects.contains(value))
      } yield result).getOrElse(failedClaim("sub"))
    }
  }
}
