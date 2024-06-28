/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require("circom_tester/wasm/tester");

import path from "path";
import assert from "assert";
import {
  sha256Pad,
  generatePartialSHA,
} from "@zk-email/helpers/dist/sha-utils";
import fs from "fs";
import crypto from "crypto";
import XmlDSigJs from "xmldsigjs";
import {
  Uint8ArrayToCharArray,
  bigIntToChunkedBytes,
  bufferToHex,
} from "@zk-email/helpers/dist/binary-format";

require("dotenv").config();

XmlDSigJs.Application.setEngine("OpenSSL", globalThis.crypto);

const xml = fs.readFileSync(
  path.join(__dirname, "./test-data", "pan.xml"),
  "utf8",
);

async function prepareTestData() {
  let doc = XmlDSigJs.Parse(xml);
  let signature = doc.getElementsByTagNameNS(
    "http://www.w3.org/2000/09/xmldsig#",
    "Signature",
  );
  let signedXml = new XmlDSigJs.SignedXml(doc);
  signedXml.LoadXml(signature[0]);

  // @ts-ignore
  const publicKey = (await signedXml.GetPublicKeys())[0];
  const publicKeyJWK = await crypto.subtle.exportKey("jwk", publicKey);
  const pubKeyBigInt = BigInt(
    "0x" + Buffer.from(publicKeyJWK.n as string, "base64").toString("hex"),
  );

  const references = signedXml.XmlSignature.SignedInfo.References.GetIterator();
  if (references.length !== 1) {
    throw new Error("XML should have exactly one reference");
  }

  // @ts-ignore
  const signedData = signedXml.ApplyTransforms(
    references[0].Transforms,
    doc.documentElement,
  );

  // @ts-ignore
  const signedInfo = signedXml.TransformSignedInfo(signedXml);

  const signatureB64 = signature[0].getElementsByTagName("SignatureValue")[0]
    .textContent as string;
  const signatureBuff = Buffer.from(signatureB64, "base64");
  const signatureBigInt = BigInt('0x' + signatureBuff.toString("hex"));

  const signedDataHaser = crypto.createHash("sha256");
  signedDataHaser.update(signedData);
  const signedDataHash = signedDataHaser.digest("base64");

  const dataHashIndex = signedInfo.indexOf(signedDataHash);
  if (dataHashIndex === -1) {
    throw new Error("Body hash not found SignedInfo");
  }

  // Local verification (optional)
  const rsaResult = crypto.verify(
    "RSA-SHA1",
    Buffer.from(signedInfo),
    publicKey,
    signatureBuff,
  );

  assert(rsaResult, "Local: RSA verification failed");

  // inputs
  const [signedDataPadded, signedDataPaddedLength] = sha256Pad(Buffer.from(signedData), 512 * 4)
  const signedInfoArr = Uint8Array.from(Buffer.from(signedInfo));

  const inputs =  {
    dataPadded: Uint8ArrayToCharArray(signedDataPadded),
    dataPaddedLength: signedDataPaddedLength,
    signedInfo: Uint8ArrayToCharArray(signedInfoArr),
    dataHashIndex: dataHashIndex,
    signature: bigIntToChunkedBytes(signatureBigInt, 121, 17),
    pubKey: bigIntToChunkedBytes(pubKeyBigInt, 121,17),
  }

  return { inputs };
}

describe("DigiLockerVerifier", function () {
  this.timeout(0);

  let circuit: any;

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

  it("should generate witness for circuit with Sha256RSA signature", async () => {
    const { inputs } = await prepareTestData();

    console.log(inputs)

    // await circuit.calculateWitness(inputs)
  });
});
