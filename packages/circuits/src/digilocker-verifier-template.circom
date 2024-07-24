pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./helpers/constants.circom";
include "./helpers/signature.circom";
include "./helpers/extractor.circom";


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

  signal output pubkeyHash;
  signal output documentType;
  signal output reveal;


  // Assert dataPaddedLength fit in maxDataLength
  component n2bDataLength = Num2Bits(log2Ceil(maxDataLength));
  n2bDataLength.in <== dataPaddedLength;


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


  // Extract
  component extractor = Extractor(n, k, maxDataLength);
  extractor.dataPadded <== dataPadded;
  extractor.certificateDataNodeIndex <== certificateDataNodeIndex;
  extractor.documentTypeLength <== documentTypeLength;
  extractor.isRevealEnabled <== isRevealEnabled;
  extractor.revealStartIndex <== revealStartIndex;
  extractor.revealEndIndex <== revealEndIndex;
  documentType <== extractor.documentType;
  reveal <== extractor.reveal;


  // Assert data between dataPaddedLength and maxDataLength is zero
  AssertZeroPadding(maxDataLength)(dataPadded, dataPaddedLength);
}
