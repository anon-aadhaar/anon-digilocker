pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/utils/array.circom";
include "./sha1.circom";


template SignatureVerifier(n, k, maxDataLength) {
	var signedInfoMaxLength = 563;

	signal input dataPadded[maxDataLength];
	signal input dataPaddedLength;
	signal input signedInfo[signedInfoMaxLength];
	signal input dataHashIndex;
	signal input signature[k];
	signal input pubKey[k];

	signal output pubkeyHash;

  // Hash the data
  // component dataHasher = Sha256Bytes(maxDataLength);
  // dataHasher.paddedIn <== dataPadded;
  // dataHasher.paddedInLength <== dataPaddedLength;
  // signal dataHash[256];
  // dataHash <== dataHasher.out;

	// TODO Assert hash is present in the signed info in the given index
	// component shifter = VarShiftLeft(signedInfoMaxLength, signedInfoMaxLength - );
	// shifter.in <== nDelimitedData;
	// shifter.shift <== startDelimiterIndex;

  component signedInfoHasher = Sha1Bytes(signedInfoMaxLength);
  signedInfoHasher.in <== signedInfo;
  signal signedInfoHash[160];
  signedInfoHash <== signedInfoHasher.out;

  var rsaMsgLength = (160 + n) \ n;
  component rsaBaseMsg[rsaMsgLength];
  for (var i = 0; i < rsaMsgLength; i++) {
      rsaBaseMsg[i] = Bits2Num(n);
  }
  for (var i = 0; i < 160; i++) {
      rsaBaseMsg[i \ n].in[i % n] <== signedInfoHash[159 - i];
  }
  for (var i = 160; i < n * rsaMsgLength; i++) {
      rsaBaseMsg[i \ n].in[i % n] <== 0;
  }

  component rsa = RSAVerifier65537(n, k);

  for (var i = 0; i < rsaMsgLength; i++) {
      rsa.message[i] <== rsaBaseMsg[i].out;
  }
  for (var i = rsaMsgLength; i < k; i++) {
      rsa.message[i] <== 0;
  }

  rsa.modulus <== pubKey;
  rsa.signature <== signature;

  // Calculate Poseidon hash of the public key (609 constraints)
  // Poseidon component can take only 16 inputs, so we convert k chunks to k/2 chunks.
  // We are assuming k is > 16 and <= 32 (i.e we merge two consecutive item in array to bring down the size)
  var poseidonInputSize = k \ 2;
  if (k % 2 == 1) {
      poseidonInputSize++;
  }
  assert(poseidonInputSize <= 16);

  signal pubkeyHasherInput[poseidonInputSize];
  for (var i = 0; i < poseidonInputSize; i++) {
      if (i == poseidonInputSize - 1 && k % 2 == 1) {
          pubkeyHasherInput[i] <== pubKey[i * 2];
      } else {
          pubkeyHasherInput[i] <== pubKey[i * 2] + (1 << n) * pubKey[i * 2 + 1];
      }
  }
  component pubkeyHasher = Poseidon(poseidonInputSize);
  pubkeyHasher.inputs <== pubkeyHasherInput;
  pubkeyHash <== pubkeyHasher.out;
}
