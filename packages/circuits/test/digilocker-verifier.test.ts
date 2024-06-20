/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require('circom_tester/wasm/tester')

import path from 'path'
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils'
import {
  bigIntToChunkedBytes,
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format'
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
  timestampToUTCUnix,
} from '@anon-aadhaar/core'
import fs from 'fs'
import crypto from 'crypto'
import assert from 'assert'
import { buildPoseidon } from 'circomlibjs'
import { bytesToIntChunks, padArrayWithZeros, bigIntsToString } from './util'
// eslint-disable-next-line @typescript-eslint/no-var-requires
require('dotenv').config()

let useTestData = true
let QRData: string = testQRData
if (process.env.REAL_DATA === 'true') {
  useTestData = false
  if (typeof process.env.DIGILOCKER_DATA === 'string') {
    QRData = process.env.DIGILOCKER_DATA
  } else {
    throw Error('You must set .env var DIGILOCKER_DATA when using real data.')
  }
}


function prepareTestData() {
  const qrDataBytes = convertBigIntToByteArray(BigInt(QRData))
  const decodedData = decompressByteArray(qrDataBytes)

  const signatureBytes = decodedData.slice(
    decodedData.length - 256,
    decodedData.length,
  )

  const signedData = decodedData.slice(0, decodedData.length - 256)

  const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3)

  const delimiterIndices: number[] = []
  for (let i = 0; i < qrDataPadded.length; i++) {
    if (qrDataPadded[i] === 255) {
      delimiterIndices.push(i)
    }
    if (delimiterIndices.length === 18) {
      break
    }
  }

  const signature = BigInt(
    '0x' + bufferToHex(Buffer.from(signatureBytes)).toString(),
  )

  const pkPem = fs.readFileSync(
    path.join(__dirname, '../assets', getCertificate(useTestData)),
  )
  const pk = crypto.createPublicKey(pkPem)

  const pubKey = BigInt(
    '0x' +
      bufferToHex(
        Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'),
      ),
  )

  const inputs = {
    xmlDataPadded: Uint8ArrayToCharArray(xmlDataPadded),
    xmlDataPaddedLength: xmlDataPaddedLen,
    signature: splitToWords(signature, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
  }

  return {
    inputs,
    xmlDataPadded,
    signedData,
    pubKey,
    xmlDataPaddedLen,
  }
}

describe('DigiLockerVerifier', function () {
  this.timeout(0)

  let circuit: any

  this.beforeAll(async () => {
    const pathToCircuit = path.join(
      __dirname,
      '../src',
      'digilocker-verifier.circom',
    )
    circuit = await circom_tester(pathToCircuit, {
      recompile: true,
      // output: path.join(__dirname, '../build'),
      include: [
        path.join(__dirname, '../node_modules'),
        path.join(__dirname, '../../../node_modules'),
      ],
    })
  })

  it('should generate witness for circuit with Sha256RSA signature', async () => {
    const { inputs } = prepareTestData()

    await circuit.calculateWitness(inputs)
  })
})
