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
  const signatureBigInt = BigInt("0x" + signatureBuff.toString("hex"));

  const signedDataHaser = crypto.createHash("sha256");
  signedDataHaser.update(signedData);
  const signedDataHash = signedDataHaser.digest("base64");

  const dataHashIndex = signedInfo.indexOf(signedDataHash);
  if (dataHashIndex === -1) {
    throw new Error("Body hash not found SignedInfo");
  }

  // Local verification
  const sha1 = crypto.createHash("sha1");
  sha1.update(Buffer.from(signedInfo));

  // Prepare the padded message as per PKCS1v1.5
  const ASN1_PREFIX_SHA1 = Buffer.from("3021300906052b0e03021a05000414", "hex");
  const hashWithPrefx = Buffer.concat([ASN1_PREFIX_SHA1, sha1.digest()]);
  const paddingLength = 256 - hashWithPrefx.length - 3; // = 218; 3 bytes for 0x00 and 0x01 and 0x00
  const paddedMessage = Buffer.concat([
    Buffer.from([0x00, 0x01]),
    Buffer.alloc(paddingLength, 0xff),
    Buffer.from([0x00]),
    hashWithPrefx,
  ]);
  const paddedMessageBigInt = BigInt("0x" + paddedMessage.toString("hex"));
  const exponent = BigInt(
    "0x" + Buffer.from(publicKeyJWK.e!, "base64").toString("hex"),
  ); // 65537

  const rsaResult =
    paddedMessageBigInt === signatureBigInt ** exponent % pubKeyBigInt;

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
      "../src",
      "digilocker-verifier.circom",
    );
    circuit = await circom_tester(pathToCircuit, {
      recompile: true,
      // output: path.join(__dirname, '../build'),
      include: [
        path.join(__dirname, "../node_modules"),
        path.join(__dirname, "../../../node_modules"),
      ],
    });
  });

  it("should generate witness for circuit with Sha256RSA signature", async () => {
    const { inputs } = await prepareTestData();

    console.log(inputs);

    await circuit.calculateWitness(inputs);
  });
});
