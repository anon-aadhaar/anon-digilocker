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
} from "@zk-email/helpers/dist/binary-format";
import { bigIntsToString } from "./util";

require("dotenv").config();

XmlDSigJs.Application.setEngine("OpenSSL", globalThis.crypto);

const xml = fs.readFileSync(
  path.join(__dirname, "./test-data", "driving-license.xml"),
  "utf8",
);

async function prepareTestData() {
  const MAX_INPUT_LENGTH = 512 * 2; // Should be adjusted based in the <CertificateData> node length

  // Parse XML
  let doc = XmlDSigJs.Parse(xml);
  let signature = doc.getElementsByTagNameNS(
    "http://www.w3.org/2000/09/xmldsig#",
    "Signature",
  );
  let signedXml = new XmlDSigJs.SignedXml(doc);
  signedXml.LoadXml(signature[0]);

  // Extract public key from the XML
  // @ts-ignore
  const publicKey = (await signedXml.GetPublicKeys())[0];
  const publicKeyJWK = await crypto.subtle.exportKey("jwk", publicKey);
  const pubKeyBigInt = BigInt(
    "0x" + Buffer.from(publicKeyJWK.n as string, "base64").toString("hex"),
  );

  // Get the signed data
  const references = signedXml.XmlSignature.SignedInfo.References.GetIterator();
  if (references.length !== 1) {
    throw new Error("XML should have exactly one reference");
  }
  // @ts-ignore
  const signedData: string = signedXml.ApplyTransforms(
    references[0].Transforms,
    doc.documentElement,
  );

  // Precompute SHA-256 hash of signed data till <CertificateData> node
  const signedDataUint8 = Uint8Array.from(Buffer.from(signedData));
  const bodySHALength = Math.floor((signedDataUint8.length + 63 + 65) / 64) * 64;
  const [signedDataPadded, signedDataPaddedLength] = sha256Pad(
    signedDataUint8,
    Math.max(MAX_INPUT_LENGTH, bodySHALength),
  );
  const {
    bodyRemaining: signedDataAfterPrecompute,
    bodyRemainingLength: signedDataAfterPrecomputeLength,
    precomputedSha,
  } = generatePartialSHA({
    body: signedDataPadded,
    bodyLength: signedDataPaddedLength,
    selectorString: "<CertificateData>", // String to split the body
    maxRemainingBodyLength: MAX_INPUT_LENGTH,
  });

  // Extract SignedInfo node and signature
  // @ts-ignore
  const signedInfo = signedXml.TransformSignedInfo(signedXml);
  const signatureB64 = signature[0].getElementsByTagName("SignatureValue")[0]
    .textContent as string;
  const signatureBuff = Buffer.from(signatureB64, "base64");
  const signatureBigInt = BigInt("0x" + signatureBuff.toString("hex"));


  // ----- Local verification : Ensure data hash is present in SignedInfo and verify RSA
  const signedDataHaser = crypto.createHash("sha256");
  signedDataHaser.update(signedData);
  const signedDataHash = signedDataHaser.digest("base64");

  const dataHashIndex = signedInfo.indexOf(signedDataHash);
  assert(dataHashIndex !== -1, "Body hash not found SignedInfo");

  const sha1 = crypto.createHash("sha1");
  sha1.update(Buffer.from(signedInfo));

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

  const rsaResult = paddedMessageBigInt === signatureBigInt ** exponent % pubKeyBigInt;
  assert(rsaResult, "Local: RSA verification failed");

  // ----- End Local verification


  // Extract <CertificateNode> and <DocumentType>
  const signedDataAfterPrecomputeBuff = Buffer.from(signedDataAfterPrecompute);
  const signedInfoArr = Uint8Array.from(Buffer.from(signedInfo));
  const certificateDataNodeIndex = signedDataAfterPrecomputeBuff.indexOf(Buffer.from("<CertificateData>"));
  const documentTypeNodeIndex = certificateDataNodeIndex + 17 + 1;

  // Data from 17 + 2 to next "space" or ">"
  const documentType = signedDataAfterPrecomputeBuff.slice(
    documentTypeNodeIndex,
    Math.min(
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(" "), documentTypeNodeIndex),
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(">"), documentTypeNodeIndex),
    ),
  );


  // Circuit inputs
  const inputs = {
    dataPadded: Uint8ArrayToCharArray(signedDataAfterPrecompute),
    dataPaddedLength: signedDataAfterPrecomputeLength,
    signedInfo: Uint8ArrayToCharArray(signedInfoArr),
    precomputedSHA: Uint8ArrayToCharArray(precomputedSha),
    dataHashIndex: dataHashIndex,
    certificateDataNodeIndex: certificateDataNodeIndex,
    documentTypeLength: documentType.length,
    signature: bigIntToChunkedBytes(signatureBigInt, 121, 17),
    pubKey: bigIntToChunkedBytes(pubKeyBigInt, 121, 17),
  };

  return { inputs, documentType };
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

  it("should verify the signature and extract document type", async () => {
    const { inputs, documentType } = await prepareTestData();

    console.log(inputs);

    const witness = await circuit.calculateWitness(inputs);
    const documentTypeWitness = bigIntsToString([witness[1]]);

    assert(
      documentTypeWitness == documentType.toString(),
      `Document type mismatch: ${documentTypeWitness} != ${documentType}`,
    );

    console.log("Witness generated for document: ", documentType);
  });
});
