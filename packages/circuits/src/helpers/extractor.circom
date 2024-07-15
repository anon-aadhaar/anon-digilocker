pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "@zk-email/circuits/utils/array.circom";
include "@zk-email/circuits/utils/bytes.circom";


template Extractor(n, k, maxDataLength) {
  signal input dataPadded[maxDataLength];
  signal input certificateDataNodeIndex;
  signal input documentTypeLength;

  signal output documentType;

  // Shift left till "<CertificateData>" node
  component certificateDataNodeShifter = VarShiftLeft(maxDataLength, maxDataLength);
  certificateDataNodeShifter.in <== dataPadded;
  certificateDataNodeShifter.shift <== certificateDataNodeIndex;
  signal shitedData[maxDataLength] <== certificateDataNodeShifter.out;

  // Assert first 17 bytes are "<CertificateData>"
  component certficateDataEquals[17];
  var certificateData[17] = [60, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 68, 97, 116, 97, 62];
  for (var i = 0; i < 17; i++) {
    certficateDataEquals[i] = IsEqual();
    certficateDataEquals[i].in <== [certificateData[i], shitedData[i]];
    certficateDataEquals[i].out === 1;
  }

  // Extract the document type - Starts from 18th bytes from "<CertificateData>"
  component documentTypeSelector = SelectSubArray(maxDataLength, 32);
  documentTypeSelector.in <== shitedData;
  documentTypeSelector.startIndex <== 17 + 1; // 17 bytes for "<CertificateData>" + 1 for a "<"
  documentTypeSelector.length <== documentTypeLength + 1; // Add 1 byte extra which would be " " or ">"

  // Assert chat after documentTypeLength is " " or ">"
  signal charAfterDocumentType <== ItemAtIndex(32)(documentTypeSelector.out, documentTypeLength);
  signal isSpace <== IsEqual()([charAfterDocumentType, 32]); // Space
  signal isGreaterThan <== IsEqual()([charAfterDocumentType, 62]); // Greater than
  (1 - isSpace) * (1 - isGreaterThan) === 0;

  // Pack documentType as a number (remove the last byte which is " " or ">")
  // Can pack up to 31 bytes in a single number (field element)
  component documentTypePacker = PackByteSubArray(32, 31);
  documentTypePacker.in <== documentTypeSelector.out;
  documentTypePacker.startIndex <== 0;
  documentTypePacker.length <== documentTypeLength; // Remove the last byte
  documentType <== documentTypePacker.out[0];
}
