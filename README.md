# Anon DigiLocker

Anon DigiLocker is a protocol for proving ownership of identity documents in DigiLocker by selectively revealing information in the doc.

We create Zero Knowledge Proof of signed XML documents from DigiLocker. Proof generation happens entirely on the browser meaning no data has to be sent to a server. The proof can be verified on-chain and off-chain.

It is recommended to use this alongside [Anon Aadhaar](https://github.com/anon-aadhaar/anon-aadhaar)

<br />

**Demo: [https://anon-digilocker.vercel.app/](https://anon-digilocker.vercel.app/)**

<br />

## How it works

- DigiLocker documents are issued with XML signatures.
- The signature process works like this - the certificate data is signed using SHA256, and the hash is added to the `<SignedInfo>` node, which is then signed under SHA1-RSA.
- The circuits take in
  - The signed data of the XML
  - `<SignedInfo>` node
  - Signature and Public key
  - and more...
- The circuit generates the `SHA256` hash of the signed data, ensures it is present in the `<SignedInfo>` node, generates the `SHA1` hash of the `<SignedInfo>` node, and verifies the RSA signature of `SHA1` hash with the public key.
- The circuit extracts the type of document (`PAN`, `DrivingLicense`, etc), computes a nullifier, and reveals data between the start and end indices as set by the prover.

<br />

## Fetching Digilocker XMl Document

1. Open DigiLocker app and go to the "Issued" tab.
2. Find the document you want to make proof of and choose "Download XML" from the menu.
3. Copy the XML and save it as `xml` file 
4. You can save it in the `/packages/circuits/test/test-data` folder and run `yarn test` to test with your document.

<br />

## 📦 Packages

This repo contains the core ZK circuits of Anon DigiLocker and JS SDK for developers to integrate into their applications. 

The following packages are available, and published to npm:

- [@anon-digilocker/circuits](packages/circuits/) - ZK circuits of Anon DigiLocker written in circom
- [@anon-digilocker/core](packages/core/) - JS SDK to generate and verify Anon DigiLocker proofs
- [@anon-digilocker/contracts](packages/contracts/) - Solidity contracts to verify Anon DigiLocker proofs


<br />

## Building and Running locally

Below steps are for building Anon DigiLocker circuits locally and generating proof with it.

For production, always use the published npm packages.

#### Requirements:

- Node JS (v18 or higher)
- Yarn

#### Install dependencies

```
yarn install
```

#### Build circuit and generate zkey

```sh
# PWD = packages/circuits

yarn build
yarn trusted-setup
```

This will generate the `build` folder with the compiled circuit and artifacts. The generated `zkey` is only meant for testing and should not be used in production.

⚠️ This will take a couple of minutes to finish.

#### Generate Witness

The below command will generate input for PAN documents and reveal data between `num=` and `"` (which is the PAN card number). Note that the revealed data contains the start/end selectors as well.

```sh
# PWD = packages/circuits

XML_PATH=test/test-data/pan.xml REVEAL_START='num="' REVEAL_END='"' NULLIFIER_SEED=123  yarn gen-witness

```

#### Generate Proof

```sh
# PWD = packages/circuits

yarn gen-proof
```

This will generate and save the proof to `packages/circuits/build/proofs/proof.json` and the public signals to `packages/circuits/build/proofs/public.json`


#### Verify the proof
```sh
# PWD = packages/circuits

yarn verify-proof
```
This will verify the generated proof and print the result to the console.

#### Verify on-chain

You can also generate the solidity verifier contract using `yarn gen-contract` and deploy it to a blockchain to verify the proof on-chain. You can use [this](https://github.com/anon-aadhaar/anon-aadhaar/blob/main/packages/core/src/utils.ts#L45) method to convert the generated proof to a format that can be used in the contract.

<br />

## Our Community

- PSE Discord server: <a href="https://discord.com/invite/sF5CT5rzrR"><img src="https://img.shields.io/badge/discord-pse-blue"></a>
- Twitter account: <a href="https://twitter.com/AnonDigiLocker"><img src="https://img.shields.io/twitter/follow/Anon_Aadhaar?style=flat-square&logo=twitter"></a>
- Telegram group: <a href="https://t.me/anon_aadhaar"><img src="https://img.shields.io/badge/telegram-@anon_aadhaar-blue.svg?style=flat-square&logo=telegram"></a>

Please join our Telegram group to receive updates, ask questions, get support with integration, etc.

<br />

## License

[MIT](https://choosealicense.com/licenses/mit/)
