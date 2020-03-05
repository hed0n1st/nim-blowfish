
import blowfish/[constants, utils]

export utils

type
  BlowfishCTX* = object
    mode: string
    iv: seq[byte]
    p: array[18, uint32]
    s: array[0..3, array[256, uint32]]
    s0, s1, s2, s3: array[256, uint32]

proc funcF(ctx: BlowfishCTX, x: uint32): uint32 =
  let
    a = ashr(x.int, 24) and 0xFF
    b = ashr(x.int, 16) and 0xFF
    c = ashr(x.int, 8) and 0xFF
    d = x.int and 0xFF

  var res = sumMod32(ctx.s[0][a], ctx.s[1][b])
  res = res xor ctx.s[2][c]
  result = sumMod32(res, ctx.s[3][d])

proc encryptBlock(ctx: var BlowfishCTX, t: array[0..1, uint32]): array[0..1, uint32] =
  result = t
  var swap: uint32
  var i = 0

  while i < 16:
    result[0] = result[0] xor ctx.p[i]
    result[1] = result[1] xor funcF(ctx, result[0])
    result = result.swap()
    inc i

  result = result.swap()

  result[0] = result[0] xor ctx.p[17]  
  result[1] = result[1] xor ctx.p[16]

proc decryptBlock(ctx: var BlowfishCTX, t: array[0..1, uint32]): array[0..1, uint32] =
  result = t
  var swap: uint32
  var i = 17

  while i > 1:
    result[0] = result[0] xor ctx.p[i]
    result[1] = result[1] xor funcF(ctx, result[0])
    result = result.swap()
    dec i

  result = result.swap()

  result[0] = result[0] xor ctx.p[0]
  result[1] = result[1] xor ctx.p[1]

proc setIv(iv: string | seq[int] | array[0..7, int]): seq[byte] =
  if iv.len != 8:
    echo "iv must be a string / seq[int] 8 bytes length or array[8, int]"
    quit()
  result = toSeqByte(iv)
    
proc encodeECB*(ctx: var BlowfishCTX, toEnc: string | seq[byte]): seq[byte] =
  var seqtoEnc: seq[byte]
  when toEnc.type is string:
    seqtoEnc = toEnc.toSeqByte()
                      .paddingNull()

  when toEnc.type is seq[byte]:
    seqtoEnc = toEnc.paddingNull()

  var i = 0
  var t: array[0..1, uint32]  
  
  while i < seqtoEnc.len:
    t[0] = packFourBytes(seqtoEnc[i], seqtoEnc[i + 1], seqtoEnc[i + 2], seqtoEnc[i + 3])
    t[1] = packFourBytes(seqtoEnc[i + 4], seqtoEnc[i + 5], seqtoEnc[i + 6], seqtoEnc[i + 7])
    t = ctx.encryptBlock(t)
    for u in 0..3:
      result.add(unpackFourBytes(t[0])[u])
    for u in 0..3:
      result.add(unpackFourBytes(t[1])[u])
    i += 8

proc encodeCBC*(ctx: var BlowfishCTX, toEnc: string | seq[byte]): seq[byte] =
  var seqtoEnc: seq[byte]
  when toEnc.type is string:
    seqtoEnc = toEnc.toSeqByte()
                      .paddingNull()

  when toEnc.type is seq[byte]:
    seqtoEnc = toEnc.paddingNull()

  var prevL = packFourBytes(ctx.iv[0], ctx.iv[1], ctx.iv[2], ctx.iv[3])
  var prevR = packFourBytes(ctx.iv[4], ctx.iv[5], ctx.iv[6], ctx.iv[7])
  var i = 0
  var t: array[0..1, uint32]

  while i < seqtoEnc.len:
    t[0] = packFourBytes(seqtoEnc[i], seqtoEnc[i + 1], seqtoEnc[i + 2], seqtoEnc[i + 3])
    t[1] = packFourBytes(seqtoEnc[i + 4], seqtoEnc[i + 5], seqtoEnc[i + 6], seqtoEnc[i + 7])
    t[0] = prevL xor t[0]
    t[1] = prevR xor t[1]
    t = ctx.encryptBlock(t)
    prevL = t[0]
    prevR = t[1]
    for u in 0..3:
      result.add(unpackFourBytes(t[0])[u])
    for u in 0..3:
      result.add(unpackFourBytes(t[1])[u])
    i += 8

proc decodeECB*(ctx: var BlowfishCTX, toDec: string | seq[byte]): seq[byte] =
  var seqtoDec: seq[byte]
  when toDec.type is string:
    seqtoDec = toDec.toSeqByte()
                      .paddingNull()

  when toDec.type is seq[byte]:
    seqtoDec = toDec.paddingNull()

  var i = 0
  var t: array[0..1, uint32]

  while i < seqtoDec.len:
    t[0] = packFourBytes(seqtoDec[i], seqtoDec[i + 1], seqtoDec[i + 2], seqtoDec[i + 3])
    t[1] = packFourBytes(seqtoDec[i + 4], seqtoDec[i + 5], seqtoDec[i + 6], seqtoDec[i + 7])
    t = ctx.decryptBlock(t)
    for u in 0..3:
      result.add(unpackFourBytes(t[0])[u])
    for u in 0..3:
      result.add(unpackFourBytes(t[1])[u])
    i += 8

proc decodeCBC*(ctx: var BlowfishCTX, toDec: string | seq[byte]): seq[byte] =
  var seqtoDec: seq[byte]
  when toDec.type is string:
    seqtoDec = toDec.toSeqByte()
                      .paddingNull()

  when toDec.type is seq[byte]:
    seqtoDec = toDec.paddingNull()
  
  var prevL = packFourBytes(ctx.iv[0], ctx.iv[1], ctx.iv[2], ctx.iv[3])
  var prevR = packFourBytes(ctx.iv[4], ctx.iv[5], ctx.iv[6], ctx.iv[7])
  var prevLTmp: uint32
  var prevRTmp: uint32
  var i = 0
  var t: array[0..1, uint32]

  while i < seqtoDec.len:
    t[0] = packFourBytes(seqtoDec[i], seqtoDec[i + 1], seqtoDec[i + 2], seqtoDec[i + 3])
    t[1] = packFourBytes(seqtoDec[i + 4], seqtoDec[i + 5], seqtoDec[i + 6], seqtoDec[i + 7])
    prevLTmp = t[0]
    prevRTmp = t[1]
    t = ctx.decryptBlock(t)
    t[0] = prevL xor t[0]
    t[1] = prevR xor t[1]
    prevL = prevLTmp
    prevR = prevRTmp
    for u in 0..3:
      result.add(unpackFourBytes(t[0])[u])
    for u in 0..3:
      result.add(unpackFourBytes(t[1])[u])
    i += 8

proc newCTX*(ctx: var BlowfishCTX, key: string, iv: string | seq[int] | array[0..7, int] = "") = 
  ctx.p = ORIG_P
  ctx.s = ORIG_S
  ctx.s0 = ORIG_S[0]
  ctx.s1 = ORIG_S[1]
  ctx.s2 = ORIG_S[2]
  ctx.s3 = ORIG_S[3]
  ctx.iv = setIv(iv)

  var key = key.toSeqByte()
              .expandKey()

  var i = 0
  var j = 0
  var t: array[0..1, uint32] = [0'u32, 0'u32]
  
  while i < 18:
    var pfb = packFourBytes(key[j], key[j+1], key[j+2], key[j+3])
    ctx.p[i] = ctx.p[i] xor pfb
    j += 4
    inc i

  i = 0
  while i < 18:
    t = ctx.encryptBlock(t)
    ctx.p[i] = t[0]
    ctx.p[i + 1] = t[1]
    i += 2  

  i = 0
  while i < 4:
    j = 0
    while j < 256:
      t = ctx.encryptBlock(t)
      ctx.s[i][j] = t[0]
      ctx.s[i][j + 1] = t[1]
      j += 2
    inc i
