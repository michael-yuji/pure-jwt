package jwt

import cats.Monad

import java.util.Base64

object utils
{
  private object _base64 {
    val encoder = Base64.getUrlEncoder.withoutPadding()
    val decoder = Base64.getUrlDecoder
  }

  def b64encode(str: String) = _base64.encoder.encodeToString(str.getBytes)
  def b64encodeBytes(bytes: Array[Byte]) = _base64.encoder.encodeToString(bytes)
  def b64decode(str: String) = _base64.decoder.decode(str.getBytes)
  def b64decodeBytes(bytes: Array[Byte]) = _base64.decoder.decode(bytes)
  def b64decodeToString(str: String) = new String(_base64.decoder.decode(str.getBytes()))

  def loadPEM(pem: String): Array[Byte] = {
    val trimmed = pem
      .replaceAll("-----.*", "")
      .replaceAll("\r\n", "")
      .replaceAll("\n", "")
      .trim
    Base64.getDecoder.decode(trimmed)
  }

  object ellipticCurve
  {
    def der2concat(der: Array[Byte], bytes: Int): Array[Byte] = {
      val headerSize = if (der(1) == 0x81) 3 else 2
      def takeValueRange(offset: Int, bytes: Array[Byte]): (Int, Int) = {
        val intSize = bytes(offset + 1)
        if (bytes(offset + 2) == 0) (offset + 3, intSize - 1) else (offset + 2, intSize)
      }

      val (roff, rlen) = takeValueRange(headerSize, der)
      val (soff, slen) = takeValueRange(roff + rlen, der)

      val result = new Array[Byte](bytes * 2)
      System.arraycopy(der, roff, result, bytes - rlen, rlen)
      System.arraycopy(der, soff, result, bytes + (bytes - slen), slen)

      result
    }

    def concat2der(concatBytes: Array[Byte]): Array[Byte] = {
      val buffer = scala.collection.mutable.ArrayBuffer[Byte]()

      val (r, s) = concatBytes.splitAt(concatBytes.length/2)

      def write1Int(bytes: Array[Byte]): Unit = {
        /* trim leading 0s which does nothing to the actual value of the bytes */
        val trimmed = bytes.dropWhile(_ == 0)
        /* ans1 int tag */
        buffer += 2.byteValue
        /* if the high bit of head is 1, prepend 0x0 to indicate it's a positive integer */
        buffer ++= (
          if (trimmed.head < 0)
            Array((trimmed.length + 1).byteValue, 0.byteValue)
          else
            Array(trimmed.length.byteValue)
        )
        buffer ++= trimmed
      }

      write1Int(r)
      write1Int(s)

      buffer.prependAll(
        if (buffer.length >= 128)
          Array(48.byteValue, 0x81.byteValue, buffer.length.byteValue)
        else
          Array(48.byteValue, buffer.length.byteValue))
      buffer.toArray
    }
  }
}
