import React from "react";
import { groth16 } from "snarkjs";
import { generateInput } from "@anon-digilocker/core";

export function App() {
  const [status, setStatus] = React.useState("Ready");
  const [isAssetsDownloaded, setIsAssetsDownloaded] = React.useState(false);


  // function downloadAssets() {
  //   setStatus("Downloading assets...");
  // }

  async function handleSubmit(e) {
    e.preventDefault();
    const xml = e.target.xml.value.trim();

    setStatus("Generating input...");


    const inputs = await generateInput(xml, {
      nullifierSeed: 1,
      revealStart: 'num="',
      revealEnd: '"',
      maxInputLength: 512 * 3
    });

    setStatus("Generating proof...");

    const proof = await groth16.fullProve(
      inputs,
      "http://127.0.0.1:8080/digilocker-verifier.wasm",
      "http://127.0.0.1:8080/circuit_final.zkey",
      console
    )

    console.log(proof);

    setStatus("Verifying proof...");

    const result = await groth16.verify(
      await fetch("http://127.0.0.1:8080/vkey.json").then((res) => res.json()),
      proof.publicSignals,
      proof.proof
    );

    setStatus(result ? "Proof verified" : "Proof failed");
  }

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <textarea name="xml" id="xml" cols="30" rows="10"></textarea>

        <button type="submit">Submit</button>
      </form>

      <div>
        Status: {status}
      </div>
    </div>

  )
}
