package jwt

import io.circe.Decoder.Result
import jwt.jdkcrypto._
import jwt.utils._
import jwt.circe
import jwt.validators._
import jwt.monadless._
import jwt.circe.CirceSupport._
import org.scalatest._
import org.scalatest.funspec._
import io.circe._
import cats._
import cats.implicits.catsStdInstancesForFuture

import scala.language.higherKinds

//import _root_.TestContext._

case class TestScheme(name: String)

class SignatureTest extends AnyFunSpec
{
  val hs256_key = "your-256-bit-secret"
  val hs256_tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaXNzIjoidGVzdCIsImlhdCI6MTUxNjIzOTAyMn0.rsU27xhZYqz9vclH0JF1NwWm7OLEPnvKJHRavIBA5Fc"
  val hs384_key = "your-384-bit-secret"
  val hs384_tok = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh"
  val hs512_key = "your-512-bit-secret"
  val hs512_tok = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg"

  implicit val schemeDecoder = new Decoder[TestScheme] {
    override def apply(c: HCursor): Result[TestScheme] = c.downField("name").as[String].map(TestScheme)
  }

  def hs256_issuer = hs256.issuer[EmptyM, Json](hs256_key)

  def hs256_validator[F[_]](implicit ev: Monad[F]) = hs256.validator[F, Json](hs256_key).all(
    validateIssusers(List("test")),
    validateSubjects(List("1234567890")),
  )

  def hs256_badValidator[F[_]](implicit ev: Monad[F]) = hs256.validator[F, Json](hs256_key)
    .and(validateIssusers(List("testx")))

  describe("hs256 test future") {
    import scala.concurrent._
    import scala.concurrent.duration._

    implicit val execctx = scala.concurrent.ExecutionContext.global

    it ("should test as successful with the validation pipeline after completion") {
      val future = hs256_validator[Future].validate(hs256_tok)
      val result = Await.result(future, 3.seconds)
      assert(result == ValidToken)
    }

    it ("should be able finish validation with a asynchronous validation pipeline") {
      val validator = hs256_validator[Future].and((headers: Json, claims: Json, token: String) => {
        Future {
          Thread.sleep(2500)
          ValidToken
        }
      })

      val future = validator.validate(hs256_tok)
      val before = java.time.OffsetDateTime.now().toEpochSecond()
      val result = Await.result(future, 3.seconds)
      val after = java.time.OffsetDateTime.now().toEpochSecond()

      assert((after - before) >= 2)
      assert(result == ValidToken)
    }

    it ("should decode the token") {
      val decoder = hs256_validator[Future].decoder.mapEither(token => schemeDecoder.decodeJson(token.claims))
      val future = decoder.validate(hs256_tok)
      val result = Await.result(future, 3.seconds)

      assert(result == Right(TestScheme("John Doe")))
    }
  }

  describe("hs256 test with option") {
    val result = hs256_validator[Option].validate(hs256_tok)
    assert(result === Some(ValidToken))
  }


  describe("hs256 test with EmptyM") {


    it ("should test as successful with the validation pipeline, with EmptyM monad") {
      assert(hs256_validator[EmptyM].validateToken(hs256_tok) == ValidToken)
    }

    it ("shouldn't validate token if the validator is expecting testx") {
      assert(hs256_badValidator[EmptyM].validateToken(hs256_tok) != ValidToken)
    }

    it ("should validate the token if ether validtor or badvalidator validates the token") {
      assert(hs256_validator[EmptyM].or(hs256_badValidator[EmptyM]).validateToken(hs256_tok) == ValidToken)
    }

    it ("should not validate the token if requires both validtor and badvalidator validates the token") {
      assert(hs256_validator[EmptyM].and(hs256_badValidator[EmptyM]).validateToken(hs256_tok) != ValidToken)
    }

    it ("should decode the token") {
      val decoder = hs256_validator[EmptyM].decoder.mapEither(token => schemeDecoder.decodeJson(token.claims))
      val result = decoder.validateToken(hs256_tok)
      assert(result == Right(TestScheme("John Doe")))
    }
  }

  describe("jwt.io hs512 example") {
    val validator = hs512.validator[EmptyM, Json]("your-512-bit-secret")
    val token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.VFb0qJ1LRg_4ujbZoRMXnVkUgiuKq5KxWqNdbKq_G9Vvz-S1zZa9LPxtHWKa64zDl2ofkT8F6jBt_K4riU-fPg"

    it ("should be verified") {
      assert(validator.validate(token).value == ValidToken)
    }
  }


  describe("jwt.io hs384 example") {
    val alg = hs384.validator[EmptyM, Json]("your-384-bit-secret")
    val token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.bQTnz6AuMJvmXXQsVPrxeQNvzDkimo7VNXxHeSBfClLufmCVZRUuyTwJF311JHuh"
    it ("should be verified") {
      assert(alg.validate(token).value == ValidToken)
    }
  }

  describe("jwt test hmac") {
    val secret = "your-256-bit-secret"
    val alg = hs256.validator[EmptyM, Json](secret)
    val token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    it ("should work") {
      assert(alg.validate(token).value == ValidToken)
    }
  }


  def testAnyAssymmetric(impl: AsymmetricKeyAlgorithm, privateKey: String, publicKey: String, token: String) = {
    val (payload, sig) = token.split('.').toList match {
      case header :: claims :: sig :: Nil =>
        ((header + "." + claims), sig)
    }

    val validator = impl.validator[EmptyM, Json](publicKey)
    describe(s"test ${impl.alg}") {
      it("should verify signature correctly") {
        assert(validator.validate(token).value == ValidToken)
      }
    }
  }

  val jwtioExampleRSAPrivateKey =
    """
      |-----BEGIN PRIVATE KEY-----
      |MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCfPKKzVmN80HRs
      |GAoUxK++RO3CW8GxomrtLnAD6TN5U5WlVbCRZ1WFrizfxcz+lr/Kvjtq/v7PdVOa
      |8NHIAdxpP3bCFEQWku/1yPmVN4lKJvKv8yub9i2MJlVaBo5giHCtfAouo+v/XWKd
      |awCR8jK28dZPFlgRxcuABcW5S5pLe4X2ASI1DDMZNTW/QWqSpMGvgHydbccI3jtd
      |S7S3xjR76V/izg7FBrBYPv0n3/l3dHLS9tXcCbUW0YmIm87BGwh9UKEOlhK1NwdM
      |Iyq29ZtXovXUFaSnMZdJbge/jepr4ZJg4PZBTrwxvn2hKTY4H4G04ukmh+ZsYQaC
      |+bDIIj0zAgMBAAECggEAKIBGrbCSW2O1yOyQW9nvDUkA5EdsS58Q7US7bvM4iWpu
      |DIBwCXur7/VuKnhn/HUhURLzj/JNozynSChqYyG+CvL+ZLy82LUE3ZIBkSdv/vFL
      |Ft+VvvRtf1EcsmoqenkZl7aN7HD7DJeXBoz5tyVQKuH17WW0fsi9StGtCcUl+H6K
      |zV9Gif0Kj0uLQbCg3THRvKuueBTwCTdjoP0PwaNADgSWb3hJPeLMm/yII4tIMGbO
      |w+xd9wJRl+ZN9nkNtQMxszFGdKjedB6goYLQuP0WRZx+YtykaVJdM75bDUvsQar4
      |9Pc21Fp7UVk/CN11DX/hX3TmTJAUtqYADliVKkTbCQKBgQDLU48tBxm3g1CdDM/P
      |ZIEmpA3Y/m7e9eX7M1Uo/zDh4G/S9a4kkX6GQY2dLFdCtOS8M4hR11Io7MceBKDi
      |djorTZ5zJPQ8+b9Rm+1GlaucGNwRW0cQk2ltT2ksPmJnQn2xvM9T8vE+a4A/YGzw
      |mZOfpoVGykWs/tbSzU2aTaOybQKBgQDIfRf6OmirGPh59l+RSuDkZtISF/51mCV/
      |S1M4DltWDwhjC2Y2T+meIsb/Mjtz4aVNz0EHB8yvn0TMGr94Uwjv4uBdpVSwz+xL
      |hHL7J4rpInH+i0gxa0N+rGwsPwI8wJG95wLY+Kni5KCuXQw55uX1cqnnsahpRZFZ
      |EerBXhjqHwKBgBmEjiaHipm2eEqNjhMoOPFBi59dJ0sCL2/cXGa9yEPA6Cfgv49F
      |V0zAM2azZuwvSbm4+fXTgTMzrDW/PPXPArPmlOk8jQ6OBY3XdOrz48q+b/gZrYyO
      |A6A9ZCSyW6U7+gxxds/BYLeFxF2v21xC2f0iZ/2faykv/oQMUh34en/tAoGACqVZ
      |2JexZyR0TUWf3X80YexzyzIq+OOTWicNzDQ29WLm9xtr2gZ0SUlfd72bGpQoyvDu
      |awkm/UxfwtbIxALkvpg1gcN9s8XWrkviLyPyZF7H3tRWiQlBFEDjnZXa8I7pLkRO
      |Cmdp3fp17cxTEeAI5feovfzZDH39MdWZuZrdh9ECgYBTEv8S7nK8wrxIC390kroV
      |52eBwzckQU2mWa0thUtaGQiU1EYPCSDcjkrLXwB72ft0dW57KyWtvrB6rt1ORgOL
      |eI5hFbwdGQhCHTrAR1vG3SyFPMAm+8JB+sGOD/fvjtZKx//MFNweKFNEF0C/o6Z2
      |FXj90PlgF8sCQut36ZfuIQ==
      |-----END PRIVATE KEY-----
      |""".stripMargin

  val jwtioExampleRSAPublicKey =
    """
      |-----BEGIN PUBLIC KEY-----
      |MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
      |vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
      |aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
      |tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
      |e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
      |V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
      |MwIDAQAB
      |-----END PUBLIC KEY-----""".stripMargin

  val jwtioExampleECDSAPublicKey =
    """
      |-----BEGIN PUBLIC KEY-----
      |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
      |q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
      |-----END PUBLIC KEY-----""".stripMargin

  val jwtioExampleECDSAPrivateKey =
    """
      |-----BEGIN PRIVATE KEY-----
      |MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
      |OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
      |1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
      |-----END PRIVATE KEY-----""".stripMargin


  testAnyAssymmetric(
    rs256, jwtioExampleRSAPrivateKey, jwtioExampleRSAPublicKey,
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA"
  )

  testAnyAssymmetric(
    rs384, jwtioExampleRSAPrivateKey, jwtioExampleRSAPublicKey,
    "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.D4kXa3UspFjRA9ys5tsD4YDyxxam3l_XnOb3hMEdPDTfSLRHPv4HPwxvin-pIkEmfJshXPSK7O4zqSXWAXFO52X-upJjFc_gpGDswctNWpOJeXe1xBgJ--VuGDzUQCqkr9UBpN-Q7TE5u9cgIVisekSFSH5Ax6aXQC9vCO5LooNFx_WnbTLNZz7FUia9vyJ544kLB7UcacL-_idgRNIWPdd_d1vvnNGkknIMarRjCsjAEf6p5JGhYZ8_C18g-9DsfokfUfSpKgBR23R8v8ZAAmPPPiJ6MZXkefqE7p3jRbA--58z5TlHmH9nTB1DYE2872RYvyzG3LoQ-2s93VaVuw"
  )

  testAnyAssymmetric(
    rs512, jwtioExampleRSAPrivateKey, jwtioExampleRSAPublicKey,
    "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.JlX3gXGyClTBFciHhknWrjo7SKqyJ5iBO0n-3S2_I7cIgfaZAeRDJ3SQEbaPxVC7X8aqGCOM-pQOjZPKUJN8DMFrlHTOdqMs0TwQ2PRBmVAxXTSOZOoEhD4ZNCHohYoyfoDhJDP4Qye_FCqu6POJzg0Jcun4d3KW04QTiGxv2PkYqmB7nHxYuJdnqE3704hIS56pc_8q6AW0WIT0W-nIvwzaSbtBU9RgaC7ZpBD2LiNE265UBIFraMDF8IAFw9itZSUCTKg1Q-q27NwwBZNGYStMdIBDor2Bsq5ge51EkWajzZ7ALisVp-bskzUsqUf77ejqX_CBAqkNdH1Zebn93A"
  )

  testAnyAssymmetric(es256,
    """
      |-----BEGIN PRIVATE KEY-----
      |MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
      |OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
      |1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
      |-----END PRIVATE KEY-----""".stripMargin,
    """
      |-----BEGIN PUBLIC KEY-----
      |MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
      |q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
      |-----END PUBLIC KEY-----""".stripMargin,
    "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
  )

  testAnyAssymmetric(es384,
    """
      |-----BEGIN PRIVATE KEY-----
      |MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCAHpFQ62QnGCEvYh/p
      |E9QmR1C9aLcDItRbslbmhen/h1tt8AyMhskeenT+rAyyPhGgBwYFK4EEACKhZANi
      |AAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+T1h/2sh/fviblc/VTyrv10GEtIi5
      |qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLUPeNpbqmYZUkWGh3MLfVzLmx85ii2
      |vMU=
      |-----END PRIVATE KEY-----""".stripMargin,
    """
      |-----BEGIN PUBLIC KEY-----
      |MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
      |Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
      |1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
      |-----END PUBLIC KEY-----""".stripMargin,
    "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6ImlUcVhYSTB6YkFuSkNLRGFvYmZoa00xZi02ck1TcFRmeVpNUnBfMnRLSTgifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.cJOP_w-hBqnyTsBm3T6lOE5WpcHaAkLuQGAs1QO-lg2eWs8yyGW8p9WagGjxgvx7h9X72H7pXmXqej3GdlVbFmhuzj45A9SXDOAHZ7bJXwM1VidcPi7ZcrsMSCtP1hiN"
  )

  testAnyAssymmetric(es512,
    """
      |-----BEGIN PRIVATE KEY-----
      |MIH3AgEAMBAGByqGSM49AgEGBSuBBAAjBIHfMIHcAgEBBEIBiyAa7aRHFDCh2qga
      |9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
      |Z6LM/yKgBwYFK4EEACOhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRU
      |SexpQUsRilPNv3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJ
      |iA+TQFdmrearjMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbs
      |KrCgk6xbsp12ew==
      |-----END PRIVATE KEY-----""".stripMargin,
    """
      |-----BEGIN PUBLIC KEY-----
      |MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
      |PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
      |6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
      |Al8G7CqwoJOsW7Kddns=
      |-----END PUBLIC KEY-----""".stripMargin,
    "eyJhbGciOiJFUzUxMiIsInR5cCI6IkpXVCIsImtpZCI6InhaRGZacHJ5NFA5dlpQWnlHMmZOQlJqLTdMejVvbVZkbTd0SG9DZ1NOZlkifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.AP_CIMClixc5-BFflmjyh_bRrkloEvwzn8IaWJFfMz13X76PGWF0XFuhjJUjp7EYnSAgtjJ-7iJG4IP7w3zGTBk_AUdmvRCiWp5YAe8S_Hcs8e3gkeYoOxiXFZlSSAx0GfwW1cZ0r67mwGtso1I3VXGkSjH5J0Rk6809bn25GoGRjOPu"
  )
}
