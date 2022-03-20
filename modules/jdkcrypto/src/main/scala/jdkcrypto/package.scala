package jwt

package object jdkcrypto {
  def hs256 = SymmetricKeyAlgorithm.hs("256")
  def hs384 = SymmetricKeyAlgorithm.hs("384")
  def hs512 = SymmetricKeyAlgorithm.hs("512")

  def rs256 = AsymmetricKeyAlgorithm.rsa("256")
  def rs384 = AsymmetricKeyAlgorithm.rsa("384")
  def rs512 = AsymmetricKeyAlgorithm.rsa("512")

  def es256 = AsymmetricKeyAlgorithm.ecdsa(32)
  def es384 = AsymmetricKeyAlgorithm.ecdsa(48)
  def es512 = AsymmetricKeyAlgorithm.ecdsa(64)
}


