pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./helpers/constants.circom";
include "./helpers/signature.circom";
include "./helpers/nullifier.circom";
include "./helpers/extractor.circom";


/// @title DigiLockerVerifierTemplate
/// @notice This circuit verifies signed DigiLocker XML documents and reveal data
/// @param n RSA pubic key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input dataPadded XML data without the signature; assumes elements to be bytes; remaining space is padded with 0
/// @input dataPaddedLength Length of padded QR data
/// @input signedInfo <SignedInfo> node that contains the signature
/// @input dataHashIndex Index of the digest in the <SignedInfo> node
/// @input certificateDataNodeIndex Index of the <CertificateData> node in `dataPadded`
/// @input documentTypeLength Length of the document type
/// @input precomputedSHA Precomputed SHA hash of `dataPadded`
/// @input signature RSA signature
/// @input pubKey RSA public key
/// @input isRevealEnabled Flag to enable reveal
/// @input revealStartIndex Start index of the reveal data
/// @input revealEndIndex End index of the reveal data
/// @input nullifierSeed Nullifier seed to generate unique nullifier per application/scope
/// @input signalHash Signal hash (to sign arbitrary messages)
/// @output pubkeyHash Public key hash
/// @output nullifier Computed Nullifier
/// @output documentType Extracted document type packed as a single field element
/// @output reveal Extracted reveal data packed as a single field element
template DigiLockerVerifierTemplate(n, k, maxDataLength) {
  var signedInfoMaxLength = signedInfoMaxLength();

  signal input dataPadded[maxDataLength];
  signal input dataPaddedLength;
  signal input signedInfo[signedInfoMaxLength];
  signal input dataHashIndex;
  signal input certificateDataNodeIndex;
  signal input documentTypeLength;
  signal input precomputedSHA[32];
  signal input signature[k];
  signal input pubKey[k];
  signal input isRevealEnabled;
  signal input revealStartIndex;
  signal input revealEndIndex;
  signal input nullifierSeed;
  signal input signalHash;

  signal output pubkeyHash;
  signal output nullifier;
  signal output documentType;
  signal output reveal;


  // Assert dataPaddedLength fit in maxDataLength
  component n2bDataLength = Num2Bits(log2Ceil(maxDataLength));
  n2bDataLength.in <== dataPaddedLength;

  // Assert data between dataPaddedLength and maxDataLength is zero
  AssertZeroPadding(maxDataLength)(dataPadded, dataPaddedLength);


  // Verify the RSA signature
  component signatureVerifier = SignatureVerifier(n, k, maxDataLength);
  signatureVerifier.dataPadded <== dataPadded;
  signatureVerifier.dataPaddedLength <== dataPaddedLength;
  signatureVerifier.signedInfo <== signedInfo;
  signatureVerifier.dataHashIndex <== dataHashIndex;
  signatureVerifier.pubKey <== pubKey;
  signatureVerifier.signature <== signature;
  signatureVerifier.precomputedSHA <== precomputedSHA;
  
  pubkeyHash <== signatureVerifier.pubkeyHash;


  // Extract and reveal
  component extractor = Extractor(n, k, maxDataLength);
  extractor.dataPadded <== dataPadded;
  extractor.certificateDataNodeIndex <== certificateDataNodeIndex;
  extractor.documentTypeLength <== documentTypeLength;
  extractor.isRevealEnabled <== isRevealEnabled;
  extractor.revealStartIndex <== revealStartIndex;
  extractor.revealEndIndex <== revealEndIndex;
  documentType <== extractor.documentType;
  reveal <== extractor.reveal;

  // Calculate nullifier
  nullifier <== Nullifier()(nullifierSeed, precomputedSHA);

  // Dummy square to prevent signal tampering (in rare cases where non-constrained inputs are ignored)
  signal signalHashSquare <== signalHash * signalHash;
}
