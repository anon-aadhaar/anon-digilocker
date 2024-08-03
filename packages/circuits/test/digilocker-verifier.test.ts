/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require("circom_tester/wasm/tester");

import path from "path";
import assert from "assert";
import { sha256Pad, generatePartialSHA } from "@zk-email/helpers/dist/sha-utils";
import fs from "fs";
import crypto from "crypto";
import XmlDSigJs from "xmldsigjs";
import { Uint8ArrayToCharArray, bigIntToChunkedBytes } from "@zk-email/helpers/dist/binary-format";
import { bigIntsToString, bytesToIntChunks, padArrayWithZeros } from "./util";
import { buildPoseidon } from "circomlibjs";

require("dotenv").config();

XmlDSigJs.Application.setEngine("OpenSSL", globalThis.crypto);

const xml = fs.readFileSync(path.join(__dirname, "./test-data", "pan.xml"), "utf8");

async function prepareTestData(params: { revealStart?: string; revealEnd?: string } = {}) {
  const { revealStart, revealEnd } = params;

  const MAX_INPUT_LENGTH = 512 * 3; // Should be adjusted based in the <CertificateData> node length

  // Parse XML
  let doc = XmlDSigJs.Parse(xml);
  let signature = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
  let signedXml = new XmlDSigJs.SignedXml(doc);
  signedXml.LoadXml(signature[0]);

  // Extract public key from the XML
  // @ts-ignore
  const publicKey = (await signedXml.GetPublicKeys())[0];
  const publicKeyJWK = await crypto.subtle.exportKey("jwk", publicKey);
  const pubKeyBigInt = BigInt("0x" + Buffer.from(publicKeyJWK.n as string, "base64").toString("hex"));

  // Get the signed data
  const references = signedXml.XmlSignature.SignedInfo.References.GetIterator();
  if (references.length !== 1) {
    throw new Error("XML should have exactly one reference");
  }
  // @ts-ignore
  const signedData: string = signedXml.ApplyTransforms(references[0].Transforms, doc.documentElement);

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
  const signatureB64 = signature[0].getElementsByTagName("SignatureValue")[0].textContent as string;
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
  const exponent = BigInt("0x" + Buffer.from(publicKeyJWK.e!, "base64").toString("hex")); // 65537

  const rsaResult = paddedMessageBigInt === signatureBigInt ** exponent % pubKeyBigInt;
  assert(rsaResult, "Local: RSA verification failed");

  // ----- End Local verification

  // Extract <CertificateNode> and <DocumentType>
  const signedDataAfterPrecomputeBuff = Buffer.from(signedDataAfterPrecompute);
  const signedInfoArr = Uint8Array.from(Buffer.from(signedInfo));
  const certificateDataNodeIndex = signedDataAfterPrecomputeBuff.indexOf(Buffer.from("<CertificateData>"));
  const documentTypeNodeIndex = certificateDataNodeIndex + 17 + 1;

  // Data from 17 + 2 to next "space" or ">"
  const documentType = signedDataAfterPrecomputeBuff.subarray(
    documentTypeNodeIndex,
    Math.min(
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(" "), documentTypeNodeIndex),
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(">"), documentTypeNodeIndex),
    ),
  );

  let revealStartIndex = 0;
  let revealEndIndex = 0;
  const isRevealEnabled = revealStart && revealEnd ? 1 : 0;

  if (isRevealEnabled) {
    // Index of reveal start from "<CertificateData>"
    revealStartIndex =
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(revealStart!), certificateDataNodeIndex) -
      certificateDataNodeIndex;

    revealEndIndex =
      signedDataAfterPrecomputeBuff.indexOf(
        Buffer.from(revealEnd!),
        certificateDataNodeIndex + revealStartIndex + revealStart!.length + 1,
      ) - certificateDataNodeIndex;

    if (revealStartIndex < 0) {
      throw new Error("reveal start not found in doc");
    }
  }

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
    isRevealEnabled,
    revealStartIndex,
    revealEndIndex,
    nullifierSeed: "123",
  };

  return { inputs, documentType, signedDataAfterPrecomputeBuff, precomputedSha };
}

describe("DigiLockerVerifier", function () {
  this.timeout(0);

  let circuit: any;

  this.beforeAll(async () => {
    const pathToCircuit = path.join(__dirname, "../src", "digilocker-verifier.circom");
    circuit = await circom_tester(pathToCircuit, {
      recompile: true,
      // output: path.join(__dirname, '../build'),
      include: [path.join(__dirname, "../node_modules"), path.join(__dirname, "../../../node_modules")],
    });
  });

  it("should generate witness - verify XML signature", async () => {
    const { inputs } = await prepareTestData();

    await circuit.calculateWitness(inputs);
  });

  it("should extract document type", async () => {
    const { inputs, documentType } = await prepareTestData();

    const witness = await circuit.calculateWitness(inputs);
    const documentTypeWitness = bigIntsToString([witness[3]]);

    assert(
      documentTypeWitness == documentType.toString(),
      `Document type mismatch: ${documentTypeWitness} != ${documentType}`,
    );

    assert(witness[4] === 0n, "reveal is not zero when not enabled");

    console.log("Witness generated for document: ", documentType);
  });

  it("should extract reveal bytes for PAN card", async () => {
    // Extract `num="123123123"`
    const { inputs, signedDataAfterPrecomputeBuff } = await prepareTestData({
      revealStart: 'num="',
      revealEnd: '"',
    });

    const str = signedDataAfterPrecomputeBuff.toString();
    const expectedReveal = str.substring(
      str.indexOf("num="),
      str.indexOf("num=") + 4 + 10 + 1 + 1, // `num=` + `10 digits of PAN` + `"`
    );

    const witness = await circuit.calculateWitness(inputs);
    const revealWitness = bigIntsToString([witness[4]]);

    assert(revealWitness == expectedReveal, `Reveal bytes mismatch: ${revealWitness} != ${expectedReveal}`);

    console.log("Witness genrated with data revealed : ", revealWitness);
  });

  it("should calculate nullifier correctly", async () => {
    const { inputs, precomputedSha } = await prepareTestData({
      revealStart: 'num="',
      revealEnd: '"',
    });

    const witness = await circuit.calculateWitness(inputs);

    const precomputedShaInt = bytesToIntChunks(new Uint8Array(precomputedSha), 31);

    const poseidon = await buildPoseidon();
    const first16 = poseidon([...precomputedSha.slice(0, 16)]);
    const last16 = poseidon([...precomputedSha.slice(16, 32)]);
    const nullifier = poseidon([Number(inputs.nullifierSeed), first16, last16]);

    assert(witness[2] == BigInt(poseidon.F.toString(nullifier)));
  });
});
