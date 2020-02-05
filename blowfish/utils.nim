
proc toSeqByte*(toSeq: string): seq[byte] =
  for t in toSeq:
    result.add(byte t)

proc toSeqByte*(toSeq: array[0..7, int]): seq[byte] =
  for t in toSeq:
    result.add(t.uint8)

proc seqByteToStr*(toStr: seq[byte]): string =
  for t in toStr:
    result.add($chr(t))

proc paddingNull*(toEnc: seq[byte]): seq[byte] =
  result = toEnc
  while result.len mod 8 != 0:
    result.add(0)

proc expandKey*(key: seq[byte]): seq[byte] =
  if key.len >= 72:
    result = key
    return

  while result.len < 72:
    for i in 0..key.len-1:
      result.add(key[i])

proc packFourBytes*(byte1: byte, byte2: byte, byte3: byte, byte4: byte): uint32 =
  var packed = byte1.int shl 24 or 
                byte2.int shl 16 or
                byte3.int shl 8 or 
                byte4.int
  result = uint32(ashr(packed, 0))

proc unpackFourBytes*(pack: uint32): array[0..3, byte] =
  result = [
    byte(ashr(pack.int, 24) and 0xFF),
    byte(ashr(pack.int, 16) and 0xFF),
    byte(ashr(pack.int, 8) and 0xFF),
    byte(pack.int and 0xFF)
  ]

proc sumMod32*(a: uint32, b: uint32): uint32 =
  var sum = int((a + b) or 0)
  result = uint32(ashr(sum, 0))

proc swap*(t: array[0..1, uint32]): array[0..1, uint32] =
  result = t
  var swap: uint32
  swap = result[0]
  result[0] = result[1]
  result[1] = swap
