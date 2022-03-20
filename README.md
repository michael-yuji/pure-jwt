# Pure-JWT

Pure-jwt is a pure and functional package for issue/validate/decode JWT.
This package focus primarily focus on portability and observability, 
hence no explicit Json library dependencies at all. In fact, the only
dependency is `cats`, as `cats` implements the Monad typeclass on various
scala types and has great interoperability with all effect libraries and their
monads.

You can easily use any Json library you like / already using. You can easily 
add support to any Json libraries by implementing the `JsonDriver` typeclass. 
`circe` support is available as a separate module and is a great example (only 
17 lines with imports!) 

# Introduction

The `core` package provides a monadic framework to work with JWT (Json Web Token),
therefore you can use any of your favoured monad / effect, let it be `ZIO` or 
`cats-effect` or `monix`  as long as they can interop with `cats`.

This package also provides a `EmptyM` monad which basically just a trivial monad.
If you are not comfortable coding with Monad and expect to write synchronized code,
the `EmptyM` can provide you a much friendly interface to work with. Check scalatest
code for examples.


The `core` package along does not implement the signing algorithms directly. 
You most likely also need the `jdkcrypto` to support various algorithms. 
Supported algorithms are currently:

- `HS256`, `HS384`, `HS512`
- `RS256`, `RS384`, `RS512`
- `ES256`, `ES384`, `ES512`

This package introduces the concept of validator and issuer. Which will discussed
in the following chapters.

# Token validation

This session documents how to validate token and build your own validation pipeline,
if you only interested in using this framework directly, check the botom of this
session, or better, check the scalatest code.

A validator is basically a trait that contains a function that to determine if a 
tuple of `(jwt_headers, jwt_claims, signature)` is valid. Since the library is 
decided to be Monad aware, the type signature of such trait and function is
```scala
trait JwtValidator[M[_], J] { self =>
  def validateM[M[_], J](headers: J, claims: J, token: String): M[ValidationResult]
  ... 
}
```

where `M` is a Monad (for example `Task` in `zio` or `Future` in scala), `J` is 
the Json type you expecting (for example `io.circe.Json`). 

`ValidationResult` is a builtin `sealed trait` that defines the following cases.
Notice that for `DecodeFailure` and `InvalidToken`, developer can store any 
information about on the error.
```scala
sealed trait ValidationResult
case object ValidToken                 extends ValidationResult
case object SignatureNotMatch          extends ValidationResult
case object NotToken                   extends ValidationResult
case class  DecodeFailure[T](value: T) extends ValidationResult
case class  InvalidToken[T](value: T)  extends ValidationResult
```

By nature, `Validator` are also chainable, the following methods are provided
to build your custom validation chain:
```scala
trait JwtValidator[M[_], J] { self =>
  /* returns a new validator that returns ValidToken if all validators returns valid */
  def all(validators: JwtValidator[M, J]*): JwtValidator[M, J]
  /* returns a new validator that returns ValidToken if any validators returns valid */
  def any(validators: JwtValidator[M, J]*): JwtValidator[M, J]
  /* you get the idea */
  def and(validator: JwtValidator[M, J]):   JwtValidator[M, J]
  def or(validator: JwtValidator[M, J]):    JwtValidator[M, J]
}
```

After a validator is created, call the `validate(token)` method
```scala
def validate(token: String)(implicit ev: Monad[M], driver: JsonDriver[J]): F[ValidationResult] 
```

### Builtin validators
The `core` package defines a few validators to validate common claims such as
`exp`, `iss`, `nbf`.

The `jdkcrypto` package defines a few jwt algorithms. For example the `hs256`
instance provide an instance can you can create a validator from, that 
**only validates the token signature**.
```scala
import cats._
import jwt.jdkcrypto._
import scala.concurrent.Future
/* hs256 is from the package jdkcrypto
 * We use `Future` as the example monad, and `Json` for the example Json type
 * this validator (and any validator from $arg.validator) only validates signature
 */
val signatureValidator = hs256.validator[Future, Json]("your-token")

/* create a validator that check token expiration and signature
 *   The argument validateExp function expects an integer value eqauls to `time now`
 *   this means validateExp does not rely on system clock at all!
 */
val checkSignatureAndExp = signatureValidator.and(validateExp(1647000000 /* see comment above !! */))
```

# Decoder

Some times, you don't only want to validate if a token is valid, but you want to
extract information from the token. Given any `validator`, you can create a decoder
by using the `decoder` method. a `JwtDecoder[M, J, A]` is an object that's capable
of convert a `JwtWebToken[J]` to a type `A` wrapped in a monad `M`, and using `J` as 
the underlying Json type.

Serveral methods, such as `trymap`, `mapEither` are provided such that it is 
easier to build the decoder easier. 
```scala
final case class JsonWebToken[J](header: J, claims: J, token: String)

def decoder(implicit ev: Monad[M]) : JwtDecoder[M, J, JsonWebToken[J]]

val mydecoder = my_validator.decoder
```

For example if you want to deserialize the `claims` to `Foo`, with a `Decoder[Foo]`
from `circe`. If you haven't used `circe` before, `decodeJson(...)` returns 
a `Either[io.circe.DecodingFailure, Foo]` type. If the decoding failed
such as `decodeJson` returns a `Left` value, the `Left` value will wrap in
`DecodeFailure` of `ValidationResult`. If there are any validation failure,
the `Left` value will set to the error that fails the routine.

```scala
val fooDecoder: io.circe.Decoder[Foo] = ???
val mydecoder = my_validator.decoder.mapEither(token => fooDecoder.decodeJson(token.claims))

mydecoder.validate(my_jwt_token) // M[Either[ValidationResult, Foo]]
```

# Issuing Token

Issue token is relatively simple. This part however maybe changed in the future 
release.

A `JwtIssuer` is an instance that can sign a `JWT` token, you only need to provide
the list of claims (a list of `(String, Json)` tuple) that you want to add to the 
claims body, call `signClaims` will be enough to issue a token. The example below 
uses `circe` as `Json`, and `EmptyM` as the monad
```scala
val issuer = hs256.issuer[EmptyM, Json]("your-256-bit-secret")
val token: EmptyM[String] = issuer.signClaims(("iss" -> Json.fromString("test")), ("sub" -> Json.fromString("1234567890")))
```

The monad interface for token signing may look overkill as serializing json isn't
usually something you have to put in a effect and run. However, since an issuer
can literally be anything, as long as can generate a signature, it is possible
for an issuer need a monadic interface, for example calling `openssl` in shell,
or even sending the unsigned token to an upstream server to sign it.