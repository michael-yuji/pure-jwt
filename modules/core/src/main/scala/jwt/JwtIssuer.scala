package jwt

import cats.Monad

abstract class JwtIssuer[F[_], T](implicit ev: Monad[F]) {

  def alg: String

  def headers(implicit driver: JsonDriver[T]): Map[String, T] =
    Map("alg" -> driver.stringValue(alg), "typ" -> driver.stringValue("JWT"))

  def emitHeader(implicit driver: JsonDriver[T]): String = printJson(headers)

  def printJson(values: Map[String, T])(implicit driver: JsonDriver[T]) = {
    values.map {
      case (key, value) => s""""$key":${driver.write(value)}"""
    }.mkString("{", ",", "}")
  }

  /**
   * Provide a list of claims tuple, produce a JWT token
   * @param claims The claims to include in the JWT
   * @param driver The JsonDriver for your selected JSON engine (for example circe, json4s, ...),
   *               this is used to serialize headers and claims
   * @return
   */
  def signClaims(claims: (String, T)*)(implicit driver: JsonDriver[T]): F[String] =
  {
    signRawClaims(printJson(claims.toMap))
  }

  /**
   * Provide a JSON serialized Json, produce a JWT Token
   * @param claims The JSON serialized JWT claims, for example {"iss":"foo","sub":"bar"}
   * @param driver The JsonDriver for your selected JSON engine (for example circe, json4s, ...),
   *               this is used for serializing the JWT headers
   * @return
   */
  def signRawClaims(claims: String)(implicit driver: JsonDriver[T]): F[String] = {
    signRawHeadersAndClaims(emitHeader, claims)
  }

  /**
   * Given a json serialized headers field, and a json serialized claims field, produce
   * the JWT token wrap in specified Monad
   *
   * @param headers The JSON serialized JWT header field, e.g. {"alg":"hs256","typ":"JWT"}
   * @param claims  The JSON serialized JWT cliams field, e.g. {"iss":"foo","sub":"bar"}
   * @return The JWT token
   */
  def signRawHeadersAndClaims(headers: String, claims: String): F[String] = {
    val b64headers = utils.b64encode(headers)
    val b64claims  = utils.b64encode(claims)

    val partial    = s"$b64headers.$b64claims"

    Monad[F].map(signPayload(partial)) { (signature: Array[Byte]) =>
      val b64signature = utils.b64encodeBytes(signature)
      s"$b64headers.$b64claims.$b64signature"
    }
  }

  def signPayload(payload: String): F[Array[Byte]]
}
