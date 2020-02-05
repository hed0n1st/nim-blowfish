
import blowfish
import strformat

when isMainModule:
  var ctx: BlowfishCTX
  var key = "af681ou8eztg9o0d"
  var iv = "01234567"
  var encode = "Encoded string! is padding test ok?"

  var keySeq = key.toSeqByte()

  echo fmt"key: {keySeq}"

  ctx.newContext(key, iv)

  echo fmt"encode this: {encode}" & "\n"
  
  var encodeSeq = encode.toSeqByte()

  var encoded = ctx.encodeCBC(encode)
  var encodedSeq = ctx.encodeCBC(encodeSeq)
  echo fmt"encoded # string mode # : {encoded}"
  echo fmt"encoded # seq byte mode # : {encodedSeq}" & "\n"

  var encodedStr = encoded.seqByteToStr()
  echo fmt"encoded string: {encodedStr}" & "\n"

  var decodedSeq = ctx.decodeCBC(encodedSeq)
  var decodedStr = ctx.decodeCBC(encodedStr)
  echo fmt"decoded # seq byte mode # : {decodedSeq}"
  echo fmt"decoded # string mode # : {$decodedStr}" & "\n"

  var decSeq = decodedSeq.seqByteToStr()
  var decStr = decodedStr.seqByteToStr()

  echo fmt"decoded as seq: {decSeq}"
  echo fmt"decoded as string: {decStr}"