/* eslint-disable @typescript-eslint/no-explicit-any */
// eslint-disable-next-line @typescript-eslint/no-var-requires
const circom_tester = require("circom_tester/wasm/tester");
import path from "path";
import assert from "assert";
import fs from "fs";
import XmlDSigJs from "xmldsigjs";
import { generateInput } from "../../core/src";
import { bigIntsToString } from "./util";
import { buildPoseidon } from "circomlibjs";

// eslint-disable-next-line @typescript-eslint/no-var-requires
require("dotenv").config();

XmlDSigJs.Application.setEngine("OpenSSL", globalThis.crypto);

const xml = fs.readFileSync(path.join(__dirname, "./test-data", "pan.xml"), "utf8");

async function prepareTestData(params: { revealStart?: string; revealEnd?: string } = {}) {
  const { revealStart, revealEnd } = params;

  const MAX_INPUT_LENGTH = 512 * 3; // Should be adjusted based in the <CertificateData> node length

  const inputs = await generateInput(xml.toString(), {
    nullifierSeed: 123n,
    signal: "1",
    revealStart: revealStart,
    revealEnd: revealEnd,
    maxInputLength: MAX_INPUT_LENGTH,
  });

  const signedDataAfterPrecomputeBuff = Buffer.from(Uint8Array.from(inputs.dataPadded.map((s) => Number(s))));
  const documentTypeNodeIndex = Number(inputs.certificateDataNodeIndex) + 17 + 1;
  const documentType = signedDataAfterPrecomputeBuff.subarray(
    documentTypeNodeIndex,
    Math.min(
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(" "), documentTypeNodeIndex),
      signedDataAfterPrecomputeBuff.indexOf(Buffer.from(">"), documentTypeNodeIndex),
    ),
  );

  return { inputs, documentType, signedDataAfterPrecomputeBuff };
}

describe("DigiLockerVerifier", function () {
  // @ts-ignore
  this.timeout(0);

  let circuit: any;

  // @ts-ignore
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
    const { inputs } = await prepareTestData({
      revealStart: 'num="',
      revealEnd: '"',
    });

    const precomputedSHA = Uint8Array.from(inputs.precomputedSHA.map((s) => Number(s)));

    const witness = await circuit.calculateWitness(inputs);

    const poseidon = await buildPoseidon();
    const first16 = poseidon([...precomputedSHA.slice(0, 16)]);
    const last16 = poseidon([...precomputedSHA.slice(16, 32)]);
    const nullifier = poseidon([Number(inputs.nullifierSeed), first16, last16]);

    assert(witness[2] == BigInt(poseidon.F.toString(nullifier)));
  });
});
