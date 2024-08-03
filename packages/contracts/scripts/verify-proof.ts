/* eslint-disable @typescript-eslint/no-var-requires */

// This script is used to verify proof against deployed contract.
// Assume proof was generated using production public key.

import '@nomiclabs/hardhat-ethers'
import { ethers } from 'hardhat'
import { packGroth16Proof } from '@anon-aadhaar/core'

async function main() {
  // Assumes proof is created in below path (using scripts in packages/circuits)
  const proof = require('../../circuits/build/proofs/proof.json')
  const publicInputs = require('../../circuits/build/proofs/public.json')

  const { AnonDigiLocker } = require(
    `../deployed-contracts/${process.env.HARDHAT_NETWORK}.json`,
  ).productionPublicKey

  const signal = 1 // Signal used when generating proof

  const anonDigiLockerVerifier = await ethers.getContractAt(
    'AnonDigiLocker',
    AnonDigiLocker,
  )

  const address = await anonDigiLockerVerifier.getAddress()
  console.log(`AnonDigiLocker : ${address}`)

  console.log(
    await anonDigiLockerVerifier.verifyAnonDigiLockerProof(
      publicInputs[0],
      publicInputs[1],
      publicInputs[2],
      signal,
      packGroth16Proof(proof),
    ),
  )
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
