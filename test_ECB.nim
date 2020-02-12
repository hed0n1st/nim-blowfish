
import blowfish
import strformat

when isMainModule:
  var ctx: BlowfishCTX
  var key = "af681ou8eztg9o0d"
  var encode = "Encoded string! is padding test ok?"

  var keySeq = key.toSeqByte()

  echo fmt"key: {keySeq}"

  ctx.newContext(key)

  echo fmt"encode this: {encode}" & "\n"
  
  var encodeSeq = encode.toSeqByte()

  var encoded = ctx.encodeECB(encode)
  var encodedSeq = ctx.encodeECB(encodeSeq)
  echo fmt"encoded # string mode # : {encoded}"
  echo fmt"encoded # seq byte mode # : {encodedSeq}" & "\n"

  var encodedStr = encoded.seqByteToStr()
  echo fmt"encoded string: {encodedStr}" & "\n"

  var decodedSeq = ctx.decodeECB(encodedSeq)
  var decodedStr = ctx.decodeECB(encodedStr)
  echo fmt"decoded # seq byte mode # : {decodedSeq}"
  echo fmt"decoded # string mode # : {$decodedStr}" & "\n"

  var decSeq = decodedSeq.seqByteToStr()
  var decStr = decodedStr.seqByteToStr()

  echo fmt"decoded as seq: {decSeq}"
  echo fmt"decoded as string: {decStr}"
  