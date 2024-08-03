import { readFileSync, writeFileSync } from "fs";
import path from "path";
import { generateInput } from "@anon-digilocker/core/circuit-helpers";

const main = async () => {
  const xmlPath = process.env.XML_PATH;
  if (!xmlPath) {
    throw new Error("XML_PATH not set");
  }

  const nullifierSeed = parseInt(process.env.NULLIFIER_SEED ?? "123456789");
  const revealStart = process.env.REVEAL_START;
  const revealEnd = process.env.REVEAL_END;

  const xml = readFileSync(xmlPath).toString();
  const input = await generateInput(xml, {
    nullifierSeed,
    revealStart,
    revealEnd,
  });

  writeFileSync(path.join(__dirname, "../build/input.json"), JSON.stringify(input));
};

main();
