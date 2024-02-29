import re
from SerpentinCbcMode.data_table_values import bin2hex, r, phi, SBoxDecimalTable, LTTable, LTTableInverse, IPTable, FPTable


# --------------------------------------------------------------
# Functions used in the formal description of the cipher

def S(box, input):
    """Apply S-box number 'box' to 4-bit bitstring 'input' and return a
    4-bit bitstring as the result."""

    return SBoxBitstring[box % 8][input]
    # There used to be 32 different S-boxes in serpent-0. Now there are
    # only 8, each of which is used 4 times (Sboxes 8, 16, 24 are all
    # identical to Sbox 0, etc). Hence the %8.


def SInverse(box, output):
    """Apply S-box number 'box' in reverse to 4-bit bitstring 'output' and
    return a 4-bit bitstring (the input) as the result."""

    return SBoxBitstringInverse[box % 8][output]


def SHat(box, input):
    """Apply a parallel array of 32 copies of S-box number 'box' to the
    128-bit bitstring 'input' and return a 128-bit bitstring as the
    result."""

    result = ""
    for i in range(32):
        result = result + S(box, input[4 * i:4 * (i + 1)])
    return result


def SHatInverse(box, output):
    """Apply, in reverse, a parallel array of 32 copies of S-box number
    'box' to the 128-bit bitstring 'output' and return a 128-bit bitstring
    (the input) as the result."""

    result = ""
    for i in range(32):
        result = result + SInverse(box, output[4 * i:4 * (i + 1)])
    return result


def SBitslice(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    to the 4 input bits coming from the current position in each of the
    items in 'words'; and put the 4 output bits in the corresponding
    positions in the output words."""

    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = S(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def SBitsliceInverse(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    in reverse to the 4 output bits coming from the current position in
    each of the items in the supplied 'words'; and put the 4 input bits in
    the corresponding positions in the returned words."""

    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = SInverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def LT(input):
    """Apply the table-based version of the linear transformation to the
    128-bit string 'input' and return a 128-bit string as the result."""

    if len(input) != 128:
        raise ValueError("input to LT is not 128 bit long")

    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result


def LTInverse(output):
    """Apply the table-based version of the inverse of the linear
    transformation to the 128-bit string 'output' and return a 128-bit
    string (the input) as the result."""

    if len(output) != 128:
        raise ValueError("input to inverse LT is not 128 bit long")

    result = ""
    for i in range(len(LTTableInverse)):
        inputBit = "0"
        for j in LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result


def LTBitslice(X):
    """Apply the equations-based version of the linear transformation to
    'X', a list of 4 32-bit bitstrings, least significant bitstring first,
    and return another list of 4 32-bit bitstrings as the result."""

    X[0] = rotateLeft(X[0], 13)
    X[2] = rotateLeft(X[2], 3)
    X[1] = xor(X[1], X[0], X[2])
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = rotateLeft(X[1], 1)
    X[3] = rotateLeft(X[3], 7)
    X[0] = xor(X[0], X[1], X[3])
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = rotateLeft(X[0], 5)
    X[2] = rotateLeft(X[2], 22)

    return X


def LTBitsliceInverse(X):
    """Apply, in reverse, the equations-based version of the linear
    transformation to 'X', a list of 4 32-bit bitstrings, least significant
    bitstring first, and return another list of 4 32-bit bitstrings as the
    result."""

    X[2] = rotateRight(X[2], 22)
    X[0] = rotateRight(X[0], 5)
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = xor(X[0], X[1], X[3])
    X[3] = rotateRight(X[3], 7)
    X[1] = rotateRight(X[1], 1)
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = xor(X[1], X[0], X[2])
    X[2] = rotateRight(X[2], 3)
    X[0] = rotateRight(X[0], 13)

    return X


def IP(input):
    """
    Initial Permutation (IP):
    Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(IPTable, input)


def FP(input):
    """Apply the Final Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""

    return applyPermutation(FPTable, input)


def IPInverse(output):
    """Apply the Initial Permutation in reverse."""
    return FP(output)


def FPInverse(output):
    """Apply the Final Permutation in reverse."""
    return IP(output)


def applyPermutation(permutationTable, input):
    """Apply the permutation specified by the 128-element list
    'permutationTable' to the 128-bit bitstring 'input' and return a
    128-bit bitstring as the result."""
    if len(input) != len(permutationTable):
        raise ValueError("input size (%d) doesn't match perm table size (%d)" \
                         % (len(input), len(permutationTable)))

    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result


def R(i, BHati, KHat):
    """Apply round 'i' to the 128-bit bitstring 'BHati', returning another
    128-bit bitstring (conceptually BHatiPlus1). Do this using the
    appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    O.show("BHati", BHati, "(i=%2d) BHati" % i)

    xored = xor(BHati, KHat[i])
    O.show("xored", xored, "(i=%2d) xored" % i)

    SHati = SHat(i, xored)
    O.show("SHati", SHati, "(i=%2d) SHati" % i)

    if 0 <= i <= r - 2:
        BHatiPlus1 = LT(SHati)
    elif i == r - 1:
        BHatiPlus1 = xor(SHati, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))
    O.show("BHatiPlus1", BHatiPlus1, "(i=%2d) BHatiPlus1" % i)

    return BHatiPlus1


def RInverse(i, BHatiPlus1, KHat):
    """Apply round 'i' in reverse to the 128-bit bitstring 'BHatiPlus1',
    returning another 128-bit bitstring (conceptually BHati). Do this using
    the appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""

    O.show("BHatiPlus1", BHatiPlus1, "(i=%2d) BHatiPlus1" % i)

    if 0 <= i <= r - 2:
        SHati = LTInverse(BHatiPlus1)
    elif i == r - 1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        raise ValueError("round %d is out of 0..%d range" % (i, r - 1))
    O.show("SHati", SHati, "(i=%2d) SHati" % i)

    xored = SHatInverse(i, SHati)
    O.show("xored", xored, "(i=%2d) xored" % i)

    BHati = xor(xored, KHat[i])
    O.show("BHati", BHati, "(i=%2d) BHati" % i)

    return BHati


def RBitslice(i, Bi, K):
    """Apply round 'i' (bitslice version) to the 128-bit bitstring 'Bi' and
    return another 128-bit bitstring (conceptually B i+1). Use the
    appropriately numbered subkey(s) from the 'K' list of 33 128-bit
    bitstrings."""

    O.show("Bi", Bi, "(i=%2d) Bi" % i)

    # 1. Key mixing
    xored = xor(Bi, K[i])
    O.show("xored", xored, "(i=%2d) xored" % i)

    # 2. S Boxes
    Si = SBitslice(i, quadSplit(xored))
    # Input and output to SBitslice are both lists of 4 32-bit bitstrings
    O.show("Si", Si, "(i=%2d) Si" % i, "tlb")

    # 3. Linear Transformation
    if i == r - 1:
        # In the last round, replaced by an additional key mixing
        BiPlus1 = xor(quadJoin(Si), K[r])
    else:
        BiPlus1 = quadJoin(LTBitslice(Si))
    # BIPlus1 is a 128-bit bitstring
    O.show("BiPlus1", BiPlus1, "(i=%2d) BiPlus1" % i)

    return BiPlus1


def RBitsliceInverse(i, BiPlus1, K):
    """Apply the inverse of round 'i' (bitslice version) to the 128-bit
    bitstring 'BiPlus1' and return another 128-bit bitstring (conceptually
    B i). Use the appropriately numbered subkey(s) from the 'K' list of 33
    128-bit bitstrings."""

    O.show("BiPlus1", BiPlus1, "(i=%2d) BiPlus1" % i)

    # 3. Linear Transformation
    if i == r - 1:
        # In the last round, replaced by an additional key mixing
        Si = quadSplit(xor(BiPlus1, K[r]))
    else:
        Si = LTBitsliceInverse(quadSplit(BiPlus1))
    # SOutput (same as LTInput) is a list of 4 32-bit bitstrings

    O.show("Si", Si, "(i=%2d) Si" % i, "tlb")

    # 2. S Boxes
    xored = SBitsliceInverse(i, Si)
    # SInput and SOutput are both lists of 4 32-bit bitstrings

    O.show("xored", xored, "(i=%2d) xored" % i)

    # 1. Key mixing
    Bi = xor(quadJoin(xored), K[i])

    O.show("Bi", Bi, "(i=%2d) Bi" % i)

    return Bi


def encrypt(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the normal algorithm, and return a 128-bit ciphertext
    bitstring."""

    O.show("fnTitle", "encrypt", None, "tu")
    O.show("plainText", plainText, "plainText")
    O.show("userKey", userKey, "userKey")

    """
    Key Schedule: Serpent begins with the generation of 33 128-bit subkeys from the original key, regardless of its size (128, 192, or 256 bits). This is done through a pre-defined 
    process that includes permutations and translations.
    """
    K, KHat = makeSubkeys(userKey)
    """
    Initial Permutation: Before the first round, the plaintext block undergoes an initial permutation (IP)
     to reorder the bits, preparing the block for encryption.
    """
    BHat = IP(plainText)  # BHat_0 at this stage
    """
    Substitution: The block is divided into four 32-bit sections,
    and each section is processed through an S-box.
    There are eight different S-boxes (S0 to S7), 
    and they are used in a predefined order
    that repeats every eight rounds. The S-boxes are non-linear transformation functions that provide the algorithm with its confusion property, making the relationship between the ciphertext and the plaintext as complex as possible.

    """

    for i in range(r):
        BHat = R(i, BHat, KHat)  # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    """
    Permutation: After substitution, the output undergoes
     a permutation step, which rearranges the bits to 
     disperse the influence of each bit across the block
     , contributing to the diffusion property.

    """
    C = FP(BHat)

    O.show("cipherText", C, "cipherText")

    return C


def encryptBitslice(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the bitslice algorithm, and return a 128-bit ciphertext
    bitstring."""

    O.show("fnTitle", "encryptBitslice", None, "tu")
    O.show("plainText", plainText, "plainText")
    O.show("userKey", userKey, "userKey")

    K, KHat = makeSubkeys(userKey)

    B = plainText  # B_0 at this stage
    for i in range(r):
        B = RBitslice(i, B, K)  # Produce B_i+1 from B_i
    # B is now _r

    O.show("cipherText", B, "cipherText")

    return B


def decrypt(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the normal algorithm, and return a 128-bit
    plaintext bitstring."""

    O.show("fnTitle", "decrypt", None, "tu")
    O.show("cipherText", cipherText, "cipherText")
    O.show("userKey", userKey, "userKey")

    K, KHat = makeSubkeys(userKey)

    BHat = FPInverse(cipherText)  # BHat_r at this stage
    for i in range(r - 1, -1, -1):  # from r-1 down to 0 included
        BHat = RInverse(i, BHat, KHat)  # Produce BHat_i from BHat_i+1
    # BHat is now _0
    plainText = IPInverse(BHat)

    O.show("plainText", plainText, "plainText")
    return plainText


def decryptBitslice(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the bitslice algorithm, and return a 128-bit
    plaintext bitstring."""

    O.show("fnTitle", "decryptBitslice", None, "tu")
    O.show("cipherText", cipherText, "cipherText")
    O.show("userKey", userKey, "userKey")

    K, KHat = makeSubkeys(userKey)

    B = cipherText  # B_r at this stage
    for i in range(r - 1, -1, -1):  # from r-1 down to 0 included
        B = RBitsliceInverse(i, B, K)  # Produce B_i from B_i+1
    # B is now _0

    O.show("plainText", B, "plainText")
    return B


def makeSubkeys(userKey):
    """
    Key Schedule
    Given the 256-bit bitstring 'userKey' (shown as K in the paper, but
    we can't use that name because of a collision with K[i] used later for
    something else), return two lists (conceptually K and KHat) of 33
    128-bit bitstrings each."""

    # Because in Python I can't index a list from anything other than 0,
    # I use a dictionary instead to legibly represent the w_i that are
    # indexed from -8.

    # We write the key as 8 32-bit words w-8 ... w-1
    # ENOTE: w-8 is the least significant word
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i + 8) * 32:(i + 9) * 32]
        O.show("wi", w[i], "(i=%2d) wi" % i)

    # We expand these to a prekey w0 ... w131 with the affine recurrence

    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i - 8], w[i - 5], w[i - 3], w[i - 1],
                bitstring(phi, 32), bitstring(i, 32)),
            11)
        O.show("wi", w[i], "(i=%2d) wi" % i)

    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(r + 1):
        whichS = (r + 3 - i) % r
        k[0 + 4 * i] = ""
        k[1 + 4 * i] = ""
        k[2 + 4 * i] = ""
        k[3 + 4 * i] = ""
        for j in range(32):  # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0 + 4 * i][j] + w[1 + 4 * i][j] + w[2 + 4 * i][j] + w[3 + 4 * i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l + 4 * i] = k[l + 4 * i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(33):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4 * i] + k[4 * i + 1] + k[4 * i + 2] + k[4 * i + 3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))

        O.show("Ki", K[i], "(i=%2d) Ki" % i)
        O.show("KHati", KHat[i], "(i=%2d) KHati" % i)

    return K, KHat


def makeLongKey(k):
    """Take a key k in bitstring format. Return the long version of that
    key."""

    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        raise ValueError("Invalid key length (%d bits)" % l)

    if l == 256:
        return k
    else:
        return k + "1" + "0" * (256 - l - 1)


# --------------------------------------------------------------
# Generic bit-level primitives

# Internally, we represent the numbers manipulated by the cipher in a
# format that we call 'bitstring'. This is a string of "0" and "1"
# characters containing the binary representation of the number in
# little-endian format (so that subscripting with an index of i gives bit
# number i, corresponding to a weight of 2^i). This representation is only
# defined for nonnegative numbers (you can see why: think of the great
# unnecessary mess that would result from sign extension, two's complement
# and so on).  Example: 10 decimal is "0101" in bitstring format.

def bitstring(n, minlen=1):
    """Translate n from integer to bitstring, padding it with 0s as
    necessary to reach the minimum length 'minlen'. 'n' must be >= 0 since
    the bitstring format is undefined for negative integers.  Note that,
    while the bitstring format can represent arbitrarily large numbers,
    this is not so for Python's normal integer type: on a 32-bit machine,
    values of n >= 2^31 need to be expressed as python long integers or
    they will "look" negative and won't work. E.g. 0x80000000 needs to be
    passed in as 0x80000000L, or it will be taken as -2147483648 instead of
    +2147483648L.

    EXAMPLE: bitstring(10, 8) -> "01010000"
    """

    if minlen < 1:
        raise ValueError("a bitstring must have at least 1 char")
    if n < 0:
        raise ValueError("bitstring representation undefined for neg numbers")

    result = ""
    while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1
    if len(result) < minlen:
        result = result + "0" * (minlen - len(result))
    return result


def binaryXor(n1, n2):
    """Return the xor of two bitstrings of equal length as another
    bitstring of the same length.

    EXAMPLE: binaryXor("10010", "00011") -> "10001"
    """

    if len(n1) != len(n2):
        raise ValueError("can't xor bitstrings of different " + \
                         "lengths (%d and %d)" % (len(n1), len(n2)))
    # We assume that they are genuine bitstrings instead of just random
    # character strings.

    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result


def xor(*args):
    """Return the xor of an arbitrary number of bitstrings of the same
    length as another bitstring of the same length.

    EXAMPLE: xor("01", "11", "10") -> "00"
    """

    if args == []:
        raise ValueError("at least one argument needed")

    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result


def rotateLeft(input, places):
    """Take a bitstring 'input' of arbitrary length. Rotate it left by
    'places' places. Left means that the 'places' most significant bits are
    taken out and reinserted as the least significant bits. Note that,
    because the bitstring representation is little-endian, the visual
    effect is actually that of rotating the string to the right.

    EXAMPLE: rotateLeft("000111", 2) -> "110001"
    """

    p = places % len(input)
    return input[-p:] + input[:-p]


def rotateRight(input, places):
    return rotateLeft(input, -places)


def shiftLeft(input, p):
    """Take a bitstring 'input' of arbitrary length. Shift it left by 'p'
    places. Left means that the 'p' most significant bits are shifted out
    and dropped, while 'p' 0s are inserted in the the least significant
    bits. Note that, because the bitstring representation is little-endian,
    the visual effect is actually that of shifting the string to the
    right. Negative values for 'p' are allowed, with the effect of shifting
    right instead (i.e. the 0s are inserted in the most significant bits).

    EXAMPLE: shiftLeft("000111", 2) -> "000001"
             shiftLeft("000111", -2) -> "011100"
    """

    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else:  # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]


def shiftRight(input, p):
    """Take a bitstring 'input' and shift it right by 'p' places. See the
    doc for shiftLeft for more details."""

    return shiftLeft(input, -p)


def keyLengthInBitsOf(k):
    """Take a string k in I/O format and return the number of bits in it."""

    return len(k) * 4



# Make the reverse lookup table too
hex2bin = {}
for (bin, hex) in bin2hex.items():
    hex2bin[hex] = bin


def bitstring2hexstring(b):
    """Take bitstring 'b' and return the corresponding hexstring."""

    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4 - (l % 4))
    for i in range(0, len(b), 4):
        result = result + bin2hex[b[i:i + 4]]
    return reverseString(result)


def hexstring2bitstring(h):
    """Take hexstring 'h' and return the corresponding bitstring."""

    result = ""
    for c in reverseString(h):
        result = result + hex2bin[c]
    return result


def reverseString(s):
    # l = list(s)
    # l.reverse()
    # return string.join(l, "")
    return ''.join(reversed(s))


# --------------------------------------------------------------
# Format conversions

def quadSplit(b128):
    """Take a 128-bit bitstring and return it as a list of 4 32-bit
    bitstrings, least significant bitstring first."""

    if len(b128) != 128:
        raise ValueError("must be 128 bits long, not " + len(b128))

    result = []
    for i in range(4):
        result.append(b128[(i * 32):(i + 1) * 32])
    return result


def quadJoin(l4x32):
    """Take a list of 4 32-bit bitstrings and return it as a single 128-bit
    bitstring obtained by concatenating the internal ones."""

    if len(l4x32) != 4:
        raise ValueError("need a list of 4 bitstrings, not " + len(l4x32))

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]


# --------------------------------------------------
# Seeing what happens inside

class Observer:
    """An object of this class can selectively display the values of the
    variables you want to observe while the program is running. There are
    tags that you can switch on or off. You sprinkle show() statements
    throughout the program to show the value of a variable at a particular
    point: show() will display the relevant variable only if the
    corresponding tag is currently on. The special tag "ALL" forces all
    show() statements to display their variable."""

    typesOfVariable = {
        "tu": "unknown", "tb": "bitstring", "tlb": "list of bitstrings", }

    def __init__(self, tags=[]):
        self.tags = {}
        for tag in tags:
            self.tags[tag] = 1

    def addTag(self, *tags):
        """Add the supplied tag(s) to those that are currently active,
        i.e. those that, if a corresponding "show()" is executed, will
        print something."""

        for t in tags:
            self.tags[t] = 1

    def removeTag(self, *tags):
        """Remove the supplied tag(s) from those currently active."""
        for t in tags:
            if t in self.tags.keys():
                del self.tags[t]

    def show(self, tag, variable, label=None, type="tb"):
        """Conditionally print a message with the current value of
        'variable'. The message will only be printed if the supplied 'tag'
        is among the active ones (or if the 'ALL' tag is active). The
        'label', if not null, is printed before the value of the
        'variable'; if it is null, it is substituted with the 'tag'. The
        'type' of the 'variable' (giving us a clue on how to print it) must
        be one of Observer.typesOfVariable."""

        if label == None:
            label = tag
        if "ALL" in self.tags.keys() or tag in self.tags.keys():
            if type == "tu":
                output = repr(variable)
            elif type == "tb":
                output = bitstring2hexstring(variable)
            elif type == "tlb":
                output = ""
                for item in variable:
                    output = output + " %s" % bitstring2hexstring(item)
                output = "[" + output[1:] + "]"
            else:
                raise ValueError("unknown type: %s. Valid ones are %s" % (
                    type, self.typesOfVariable.keys()))

            print
            label,
            if output:
                print
                "=", output
            else:
                print


# We make one global observer object that is always available
O = Observer(["plainText", "userKey", "cipherText"])

# Data tables


SBoxBitstring = []
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)




def convertToBitstring(input, numBits):
    """Take a string 'input', theoretically in std I/O format, but in
    practice liable to contain any sort of crap since it's user supplied,
    and return its bitstring representation, normalised to numBits
    bits. Raise the appropriate variant of ValueError (with explanatory
    message) if anything can't be done (this includes the case where the
    'input', while otherwise syntactically correct, can't be represented in
    'numBits' bits)."""

    if re.match("^[0-9a-f]+$", input):
        bitstring = hexstring2bitstring(input)
    else:
        raise ValueError("%s is not a valid hexstring" % input)

    # assert: bitstring now contains the bitstring version of the input

    if len(bitstring) > numBits:
        # Last chance: maybe it's got some useless 0s...
        if re.match("^0+$", bitstring[numBits:]):
            bitstring = bitstring[:numBits]
        else:
            raise ValueError("input too large to fit in %d bits" % numBits)
    else:
        bitstring = bitstring + "0" * (numBits - len(bitstring))

    return bitstring


# Assume all the utility functions and constants you provided are already defined above

class SerpentEncryptor:
    def __init__(self, userKey):
        self.userKey = userKey
        self.K, self.KHat = makeSubkeys(userKey)

    def encrypt(self, plainText):
        # Convert plaintext to bitstring, assuming it's in hex format for this example
        bitstringPlaintext = hexstring2bitstring(plainText)
        encryptedBitstring = encrypt(bitstringPlaintext, self.userKey)
        # Convert back to hex string for readability
        return bitstring2hexstring(encryptedBitstring)


class SerpentDecryptor:
    def __init__(self, userKey):
        self.userKey = userKey
        self.K, self.KHat = makeSubkeys(userKey)

    def decrypt(self, cipherText):
        # Convert ciphertext to bitstring
        bitstringCiphertext = hexstring2bitstring(cipherText)
        decryptedBitstring = decrypt(bitstringCiphertext, self.userKey)
        # Convert back to hex string
        return bitstring2hexstring(decryptedBitstring)


def main():
    # Example plaintext and key in hex format
    plaintext = "0123456789abcdeffedcba9876543210"
    hexKey = "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff"

    # Convert hexKey to bitstring
    userKey = hexstring2bitstring(hexKey)
    # Ensure it's 256 bits long
    userKey = userKey.ljust(256, '0')[:256]  # Adjust as necessary based on how your bitstrings are managed

    # Initialize the encryptor and decryptor with the user key
    encryptor = SerpentEncryptor(userKey)
    decryptor = SerpentDecryptor(userKey)
    # Encrypt the plaintext
    ciphertext = encryptor.encrypt(plaintext)
    print(f"Plaintext: {plaintext}")
    print(f"Ciphertext: {ciphertext}")

    # Decrypt the ciphertext
    decryptedText = decryptor.decrypt(ciphertext)
    print(f"Decrypted Text: {decryptedText}")

    # Verify the decryption
    if plaintext.lower() == decryptedText.lower():
        print("The decryption was successful and matches the original plaintext.")
    else:
        print("The decrypted text does not match the original plaintext.")

