package jwt.circe

import jwt._
import io.circe._

object CirceSupport {
  implicit def circeSupport: JsonDriver[Json] = new JsonDriver[Json] {
    override def write(value: Json): String = value.printWith(Printer.noSpaces)
    override def stringValue(value: String): Json = Json.fromString(value)
    override def parse(source: String): Option[Json] = io.circe.parser.parse(source).toOption
    override def jsonGetLong(value: Json): Option[Long] = value.asNumber.flatMap(_.toLong)
    override def jsonGetString(value: Json): Option[String] = value.asString
    override def jsonGetBool(value: Json): Option[Boolean] = value.asBoolean
    override def jsonGetArray(value: Json): Option[List[Json]] = value.asArray.map(_.toList)
    override def getKeyed(obj: Json, key: String): Option[Json] = obj.asObject.flatMap(_.toMap.get(key))
  }
}
