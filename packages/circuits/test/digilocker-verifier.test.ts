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
  const exponent = BigInt(
    "0x" + Buffer.from(publicKeyJWK.e as string, "base64").toString("hex"),
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
  const signatureBigInt = BigInt("0x" + signatureBuff.toString("hex"));

  const signedDataHaser = crypto.createHash("sha256");
  signedDataHaser.update(signedData);
  const signedDataHash = signedDataHaser.digest("base64");

  const dataHashIndex = signedInfo.indexOf(signedDataHash);
  if (dataHashIndex === -1) {
    throw new Error("Body hash not found SignedInfo");
  }

  // const sha1 = crypto.createHash("sha1");
  // sha1.update(Buffer.from(signedInfo));
  // console.log(sha1.digest().toString("hex"))

  // console.log("message", BigInt('0x' + sha1.digest().toString("hex")))
  // console.log("signatureBigInt", signatureBigInt)
  // console.log("pubKeyBigInt", pubKeyBigInt)

  // Local verification (optional)
  // const rsaResult = crypto.verify(
  //   "RSA-SHA1",
  //   Buffer.from(signedInfo),
  //   publicKey,
  //   signatureBuff,
  // );

  // console.log("exponent", exponent);

  // const messsageBigInt = BigInt('0x' + sha1.digest().toString("hex"));
  const signatureBigInt2 = BigInt("0x" + signatureBuff.toString("hex"));

  // ASN.1 DER prefix for SHA-1
  const ASN1_PREFIX_SHA1 = Buffer.from("3021300906052b0e03021a05000414", "hex");

  // Combine ASN.1 prefix and hash
  const tBuffer = Buffer.concat([ASN1_PREFIX_SHA1, sha1.digest()]);

  // Calculate the padding length (modulus length - 3 - T length)
  const keyLength = 2048 / 8; // RSA key length in bytes (e.g., 2048 bits)
  const paddingLength = keyLength - tBuffer.length - 3;

  // console.log("paddingLength", paddingLength)

  // Create padding buffer (all 0xFF)
  const paddingBuffer = Buffer.alloc(paddingLength, 0xff);

  // Construct the full padded message
  const paddedMessage = Buffer.concat([
    Buffer.from([0x00, 0x01]),
    paddingBuffer,
    Buffer.from([0x00]),
    tBuffer,
  ]);

  // const chunkgs = bigIntToChunkedBytes(BigInt('0x' + paddedMessage.toString("hex")), 121, 17);

  // console.log(chunkgs);

  const rsaResult =
    BigInt("0x" + paddedMessage.toString("hex")) ===
    signatureBigInt2 ** exponent % pubKeyBigInt;


  // console.log("rsaResult2", rsaResult2);

  assert(rsaResult, "Local: RSA verification failed");

  // inputs
  const [signedDataPadded, signedDataPaddedLength] = sha256Pad(
    Buffer.from(signedData),
    512 * 4,
  );
  const signedInfoArr = Uint8Array.from(Buffer.from(signedInfo));

  const inputs = {
    dataPadded: Uint8ArrayToCharArray(signedDataPadded),
    dataPaddedLength: signedDataPaddedLength,
    signedInfo: Uint8ArrayToCharArray(signedInfoArr),
    dataHashIndex: dataHashIndex,
    signature: bigIntToChunkedBytes(signatureBigInt, 121, 17),
    pubKey: bigIntToChunkedBytes(pubKeyBigInt, 121, 17),
  };

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

    await circuit.calculateWitness(inputs)
  });
});
