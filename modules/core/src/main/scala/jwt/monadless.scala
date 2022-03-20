package jwt

import cats.Monad

object monadless
{
  object EmptyM {
    implicit def monad: cats.Monad[EmptyM] = new Monad[EmptyM] {
      override def flatMap[A, B](fa: EmptyM[A])(f: A => EmptyM[B]): EmptyM[B] = f(fa.value)
      override def tailRecM[A, B](a: A)(f: A => EmptyM[Either[A, B]]): EmptyM[B] = f(a).value match {
        case Left(value) => tailRecM(value)(f)
        case Right(value) => EmptyM(value)
      }

      override def pure[A](x: A): EmptyM[A] = EmptyM(x)
    }
  }

  case class EmptyM[T](value: T)
  implicit class EmptyMonadValidator[T](v: JwtValidator[EmptyM, T])
  {
    def validateToken(token: String)(implicit j: JsonDriver[T]): ValidationResult = {
      v.validate(token).value
    }
  }

  implicit class EmptyMonadDecoder[T, A](decoder: JwtDecoder[EmptyM, T, A])
  {
    def validateToken(token: String)(implicit j: JsonDriver[T]) = {
      decoder.validate(token).value
    }
  }
}
