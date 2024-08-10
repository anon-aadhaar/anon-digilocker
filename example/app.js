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

    console.log(inputs);

    setStatus("Generating proof...");

    const proof = await groth16.fullProve(
      inputs,
      "http://127.0.0.1:8080/digilocker-verifier.wasm",
      "http://127.0.0.1:8080/circuit_final.zkey",
      console
    )

    console.log(proof);

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
