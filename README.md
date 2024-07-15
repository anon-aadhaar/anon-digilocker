# Anon DigiLocker

[WIP] 

This is an exploration of creating ZK proof of documents in DigiLocker with selective disclosure.

The [circuits](/packages/circuits/) are written in Circom.


### Testing

1. Open DigiLocker app and go to the "Issued" tab.
2. Find the document you want to make proof of and chose "Download XML" from the menu.
3. Copy the XML and save it as file in the `/packages/circuits/test/test-data` folder.
4. Update the file path in the test file `digilocker-verifier.test.ts`.
5. Run the test with `yarn test`.


### How it works

- DigiLocker documents are issued with XML signatures.
- The signature process works like this - the certificate data is signed using SHA256, and the hash is added to the `<SignedInfo>` node, which is then signed under SHA1-RSA.
- The circuits take in
  - The signed data of the XML
  - `<SignedInfo>` node
  - Signature and Public key
  - and more...
- The circuit generates the SHA256 hash of the signed data, ensures its present in the `<SignedInfo>` node, generates the SHA1 hash of the `<SignedInfo>` node, and verifies the RSA signature of SHA1 hash with the public key.

- The circuit extracts the type of the document (PAN, DrivingLicense, etc) from the `<CertificateData>` node. The index for this node is also taken as an input.


### Problems

- Currently, we can only verify the document and extract the type of the document.
- We can take the same approach to extract name and other details, and also compute a meaningful `nullifier`.
- But this is not yet implemented as the size of the input is usually very large - especially due to the photo of the user in `<IssuedTo>` node.
- Large input size will lead to very large constraints and make proving unreasonable, as SHA is constraint-heavy.
- Since the `<CertificateData>` is towards the end of the signed data, we can [precompute](https://blog.aayushg.com/zkemail/#arbitrary-length-sha256-hashing) the hash up to that point.
- This is the reason why the type of the document is extracted from the `<CertificateData>` node.
- Other details of the document like name, DOB, unique identifiers that can be used to derive a `nullifier`, etc usually appear before the `IssuedTo.Photo` node; and thus cannot be extracted when doing SHA precompute.


### Solutions

- Since we have to deal with SHA-256 and large inputs, groth16 is not a good choice for this, especially since we need client-side proofs.
- A different proof system built on small/binary fields would be more efficient.
