import '@nomiclabs/hardhat-ethers'
import { ethers } from 'hardhat'
import { PUBKEY_HASH } from '@anon-digilocker/core'

async function main() {
  const verifier = await ethers.deployContract('Verifier')
  await verifier.waitForDeployment()

  const _verifierAddress = await verifier.getAddress()

  console.log(`Verifier contract deployed to ${_verifierAddress}`)

  const anonDigiLocker = await ethers.deployContract('AnonDigiLocker', [
    _verifierAddress,
    PUBKEY_HASH,
  ])

  await anonDigiLocker.waitForDeployment()
  const _anonDigiLockerAddress = await anonDigiLocker.getAddress()

  console.log(`AnonDigiLocker contract deployed to ${_anonDigiLockerAddress}`)
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
