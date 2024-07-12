pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/base64.circom";
include "@zk-email/circuits/utils/array.circom";
include "../lib/sha1.circom";


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
  component dataHasher = Sha256Bytes(maxDataLength);
  dataHasher.paddedIn <== dataPadded;
  dataHasher.paddedInLength <== dataPaddedLength;
  signal dataHash[256];
  dataHash <== dataHasher.out;


	// Assert hash is present in the signed info in the given index - shift and check first 71 elements
  // 71 = Length of (<DigestValue> + base64 encoded SHA256 hash (44) + <DigestValue>)
	component shifter = VarShiftLeft(signedInfoMaxLength, 71);
	shifter.in <== signedInfo;
	shifter.shift <== dataHashIndex;
  signal digestValueNode[71] <== shifter.out;

  // Decode 44 chars of base64 encoded SHA256 hash to 32 bytes
  component base64Decoder = Base64Decode(32);
  for (var i = 0; i < 44; i++) {
    base64Decoder.in[i] <== digestValueNode[i];
  }
  signal dataHashDecoded[32] <== base64Decoder.out;
  
  // Assert the decoded hash is equal to the hash of the data
  component dataHashBytes[32];
  for (var i = 0; i < 32; i++) {
    dataHashBytes[i] = Bits2Num(8);
  }
  for (var i = 0; i < 256; i++) {
    dataHashBytes[i \ 8].in[i % 8] <== dataHash[255 - i];
  }

  for (var i = 0; i < 32; i++) {
    dataHashBytes[31 - i].out === dataHashDecoded[i];
  }


  // Hash <SignedInfo> node
  component signedInfoHasher = Sha1Bytes(signedInfoMaxLength);
  signedInfoHasher.in <== signedInfo;
  signal signedInfoHash[160];
  signedInfoHash <== signedInfoHasher.out;


  component shaPadder = SHA1PadASN1(n);
  shaPadder.sha1Hash <== signedInfoHash;


  // Verify RSA signature with padded SHA1 hash
  component rsa = RSAVerifier65537(n, k);
  rsa.message <== shaPadder.out;
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
