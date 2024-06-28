pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "./helpers/signature.circom";


template DigiLockerVerifierTemplate(n, k, maxDataLength) {
	var signedInfoMaxLength = 563;

    signal input dataPadded[maxDataLength];
    signal input dataPaddedLength;
    signal input signedInfo[signedInfoMaxLength];
    signal input dataHashIndex;
    signal input signature[k];
    signal input pubKey[k];

    signal output pubkeyHash;
    

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
    pubkeyHash <== signatureVerifier.pubkeyHash;


    // Assert data between dataPaddedLength and maxDataLength is zero
    AssertZeroPadding(maxDataLength)(dataPadded, dataPaddedLength);
}
