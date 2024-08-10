import React from "react";
import { groth16 } from "snarkjs";
import { generateInput } from "@anon-digilocker/core";
import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import "prismjs/components/prism-markup";
import "prismjs/components/prism-clike";
import "prismjs/components/prism-xml-doc";
import "prismjs/themes/prism.css";

const ARTIFACTS_URL = "http://127.0.0.1:8080";

export function App() {
  const [xmlContent, setXmlContent] = React.useState(``);
  const [status, setStatus] = React.useState("Ready");
  const [isAssetsDownloaded, setIsAssetsDownloaded] = React.useState(false);

  // function downloadAssets() {
  //   setStatus("Downloading assets...");
  // }

  async function handleSubmit(e) {
    e.preventDefault();
    document.getElementsByClassName("btn-submit")[0].disabled = true;

    try {
      const revealStart = e.target.revealStart.value.trim();
      const revealEnd = e.target.revealEnd.value.trim();
      const nullifierSeed = parseInt(e.target.nullifierSeed.value.trim());
      const signal = e.target.signal.value.trim();

      setStatus("Generating input...");

      const inputs = await generateInput(xmlContent, {
        nullifierSeed,
        revealStart,
        revealEnd,
        signal,
      });

      setStatus("Generating proof...");

      const proof = await groth16.fullProve(
        inputs,
        `${ARTIFACTS_URL}/digilocker-verifier.wasm`,
        `${ARTIFACTS_URL}/circuit_final.zkey`,
        console,
      );

      console.log(proof);

      setStatus("Verifying proof...");

      const result = await groth16.verify(
        await fetch(`${ARTIFACTS_URL}/vkey.json`).then((res) => res.json()),
        proof.publicSignals,
        proof.proof,
      );

      setStatus(result ? "Proof verified" : "Proof failed");
    } catch (e) {
      setStatus(`Error: ${e.message}`);
    } finally {
      document.getElementsByClassName("btn-submit")[0].disabled = false;
    }
  }

  return (
    // eslint-disable-next-line react/jsx-filename-extension
    <div className="container">
      <div className="box" style={{ maxWidth: "800px", margin: "0 auto" }}>
        <h1 className="mt-3 mb-3">Anon DigiLocker</h1>

        <div className="mb-3">
          <h5>Instructions:</h5>
          <ul>
            <li>
              Open DigiLocker app and go to the <code>Issued</code> tab.
            </li>
            <li>
              Click the three dot menu icon against any document and select{" "}
              <code>Download XML</code>.
            </li>
            <li>Copy the XMl content and paste here.</li>
          </ul>
        </div>

        <form onSubmit={handleSubmit}>
          <label htmlFor="xml">DigiLocker XML</label>
          {/* <textarea className="form-control mt-2" name="xml" id="xml" style={{ width: "100%" }} rows="30"></textarea> */}
          <Editor
            value={xmlContent}
            onValueChange={(code) => setXmlContent(code)}
            highlight={(code) => highlight(code, languages.text)}
            padding={10}
            style={{
              backgroundColor: "#f5f5f5",
              fontFamily: '"Fira code", "Fira Mono", monospace',
              fontSize: 12,
              height: "400px",
              overflowY: "scroll",
            }}
          />

          <br />

          <div className="form-group">
            <label htmlFor="revealStart">Reveal Start</label>
            <input type="text" className="form-control" name="revealStart" id="revealStart" />
          </div>

          <div className="form-group">
            <label htmlFor="revealEnd">Reveal End</label>
            <input type="text" className="form-control" name="revealEnd" id="revealEnd" />
          </div>

          <div className="form-group">
            <label htmlFor="nullifierSeed">Nullifier Seed</label>
            <input
              type="text"
              defaultValue="1"
              className="form-control"
              name="nullifierSeed"
              id="nullifierSeed"
            />
          </div>

          <div className="form-group">
            <label htmlFor="signal">Signal</label>
            <input
              type="text"
              className="form-control"
              name="signal"
              id="signal"
              defaultValue={"1337"}
            />
          </div>

          <button className="btn btn-submit btn-primary mt-4" type="submit">
            Submit
          </button>
        </form>

        <div className="alert alert-light mt-5">{status}</div>
      </div>
    </div>
  );
}
