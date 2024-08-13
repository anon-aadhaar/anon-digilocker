import React from "react";
import { groth16 } from "snarkjs";
import { generateInput } from "@anon-digilocker/core";
import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import Modal from "react-bootstrap/Modal";
import Button from "react-bootstrap/Button";
import tutorialImage from "./assets/digilocker-how-to.gif";
import "prismjs/components/prism-markup";
import "prismjs/components/prism-clike";
import "prismjs/components/prism-xml-doc";
import "prismjs/themes/prism.css";

const ARTIFACTS_URL = "http://127.0.0.1:8080";

export function App() {
  const [xmlContent, setXmlContent] = React.useState(``);
  const [status, setStatus] = React.useState("Ready");
  const [showModal, setShowModal] = React.useState(false);
  const [revealStart, setRevealStart] = React.useState(0);
  const [revealEnd, setRevealEnd] = React.useState(0);

  async function handleSubmit(e) {
    e.preventDefault();
    document.getElementsByClassName("btn-submit")[0].disabled = true;

    try {
      const nullifierSeed = parseInt(e.target.nullifierSeed.value.trim());
      const signalStr = e.target.signal.value.trim();
      const signal = [...new TextEncoder().encode(signalStr)].reduce(
        (acc, byte, i) => acc + BigInt(byte) * BigInt(256) ** BigInt(i),
        BigInt(0),
      );

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

  let revealString = "";
  let revealError = "";
  if (revealStart && revealEnd) {
    const certificateDataIndex = xmlContent.indexOf("<CertificateData>");
    const revealStartIndex = xmlContent.indexOf(revealStart, certificateDataIndex);
    const revealEndIndex = xmlContent.indexOf(revealEnd, revealStartIndex + revealStart.length + 1);

    if (revealStartIndex === -1 || revealEndIndex === -1) {
      revealError = `Cannot find any data between ${revealStart} and ${revealEnd}`;
    } else {
      revealString = xmlContent.substring(revealStartIndex, revealEndIndex + 1);

      if (revealString.length > 31) {
        revealError = `Cannot reveal more than 31 characters`;
      }
    }
  }

  return (
    // eslint-disable-next-line react/jsx-filename-extension
    <div className="container">
      <div className="box" style={{ maxWidth: "800px", margin: "0 auto" }}>
        <h1 className="mt-3 mb-3">Anon DigiLocker</h1>
        <hr />

        <div className="mb-3">
          <h5>
            <span className="mr-3">Instructions </span>
            <Button
              className="btn btn-inline btn-sm btn-secondary"
              variant="primary"
              onClick={() => setShowModal(true)}
            >
              Show Video
            </Button>
          </h5>
          <ul>
            <li>
              Open DigiLocker app and go to the <code>Issued</code> tab.
            </li>
            <li>
              Click the three dot menu icon against the document you want to prove and select{" "}
              <code>Download XML</code>.
            </li>
            <li>Copy the XMl content and paste in the form below.</li>
          </ul>

          <Modal show={showModal} onHide={() => setShowModal(false)}>
            <Modal.Header closeButton>How to get DigiLocker XML</Modal.Header>
            <Modal.Body className="text-center">
              <img
                src={tutorialImage}
                alt="digilocker-how-to"
                style={{
                  width: "auto",
                  height: "auto",
                  maxHeight: "800px",
                  border: "1px solid black",
                }}
              />
            </Modal.Body>
          </Modal>
        </div>

        <hr />

        <form onSubmit={handleSubmit}>
          <label htmlFor="xml">DigiLocker XML (Paste below)</label>
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
              marginTop: "10px",
            }}
          />

          <hr />

          <div className="form-row row">
            <div>
              <h5>Selective Disclosure</h5>
              <p>
                You can reveal some data from the <code>{"<CertificateData />"}</code> node of the
                XML, as part of the proof
              </p>
              <p>
                Enter the text from which the reveal should start and end. For example, in a PAN
                Verification Record XML you can reveal your PAN number which is between{" "}
                <code>num="</code> and <code>"</code> in the XML
              </p>
            </div>
            <div className="col-md-6 mb-3">
              <label htmlFor="revealStart">Reveal Start</label>

              <input
                type="text"
                className="form-control"
                id="revealStart"
                placeholder={'num="'}
                onChange={(e) => setRevealStart(e.target.value)}
              />
            </div>

            <div className="col-md-6 mb-3">
              <label htmlFor="revealEnd">Reveal End</label>
              <input
                type="text"
                className="form-control"
                id="revealEnd"
                placeholder={'"'}
                onChange={(e) => setRevealEnd(e.target.value)}
              />
            </div>

            <div className="col-md-12">
              {revealError && (
                <div className="alert alert-danger" role="alert">
                  {revealError}
                </div>
              )}
              {revealString && !revealError && (
                <div className="alert alert-success" role="alert">
                  You are revealing <code>{revealString}</code> as part of the proof
                </div>
              )}
            </div>
          </div>

          <hr />

          <div className="form-group mb-3">
            <label htmlFor="nullifierSeed">
              Nullifier Seed (a random number for generating unique nullifier)
            </label>
            <input
              type="number"
              defaultValue="1"
              maxLength={30}
              className="form-control"
              name="nullifierSeed"
              id="nullifierSeed"
            />
          </div>

          <div className="form-group mb-3">
            <label htmlFor="signal">
              Signal (any message you want to sign as part of the proof)
            </label>
            <input type="text" className="form-control" name="signal" id="signal" />
          </div>

          <button
            disabled={!xmlContent || revealError}
            className="btn btn-submit btn-primary mt-4"
            type="submit"
          >
            Submit
          </button>
        </form>

        <div className="alert alert-light mt-3 mb-5">{status}</div>
      </div>
    </div>
  );
}
