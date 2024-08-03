import { Groth16Proof } from 'snarkjs'

export const handleError = (error: unknown, defaultMessage: string): Error => {
  if (error instanceof Error) return error

  let stringified = defaultMessage
  try {
    stringified = JSON.stringify(error)
    // eslint-disable-next-line no-empty
  } catch {}

  const err = new Error(
    `This value was thrown as is, not through an Error: ${stringified}`
  )
  return err
}

export function splitToWords(
  number: bigint,
  wordsize: bigint,
  numberElement: bigint
) {
  let t = number
  const words: string[] = []
  for (let i = BigInt(0); i < numberElement; ++i) {
    const baseTwo = BigInt(2)

    words.push(`${t % BigInt(Math.pow(Number(baseTwo), Number(wordsize)))}`)
    t = BigInt(t / BigInt(Math.pow(Number(BigInt(2)), Number(wordsize))))
  }
  if (!(t == BigInt(0))) {
    throw `Number ${number} does not fit in ${(
      wordsize * numberElement
    ).toString()} bits`
  }
  return words
}

/**
 * Packs a proof into a format compatible with AnonAadhaar.sol contract.
 * @param originalProof The proof generated with SnarkJS.
 * @returns The proof compatible with Semaphore.
 */
export function packGroth16Proof(
  groth16Proof: Groth16Proof
): bigint[] {
  return [
    groth16Proof.pi_a[0],
    groth16Proof.pi_a[1],
    groth16Proof.pi_b[0][1],
    groth16Proof.pi_b[0][0],
    groth16Proof.pi_b[1][1],
    groth16Proof.pi_b[1][0],
    groth16Proof.pi_c[0],
    groth16Proof.pi_c[1],
  ]
}

export function convertBigIntToByteArray(bigInt: bigint) {
  const byteLength = Math.max(1, Math.ceil(bigInt.toString(2).length / 8))

  const result = new Uint8Array(byteLength)
  let i = 0
  while (bigInt > 0) {
    result[i] = Number(bigInt % BigInt(256))
    bigInt = bigInt / BigInt(256)
    i += 1
  }
  return result.reverse()
}

export function convertRevealBigIntToString(input: bigint | string) {
  if (typeof input === 'string') input = BigInt(input)

  let result = ''
  while (input > 0) {
    result += String.fromCharCode(Number(input % BigInt(256)))
    input = input / BigInt(256)
  }
  // The proof input is in big endian format, on each iteration appends the last char
  // which is the first char in little-endian format
  // reversal is not needed
  return result
}
