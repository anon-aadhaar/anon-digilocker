pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/sha.circom";
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


  // Hash the signed data
  component dataHasher = Sha256Bytes(maxDataLength);
  dataHasher.paddedIn <== dataPadded;
  dataHasher.paddedInLength <== dataPaddedLength;
  signal dataHash[256];
  dataHash <== dataHasher.out;

  // Convert to bytes
  component dataHashBytes[32];
  for (var i = 0; i < 32; i++) {
    dataHashBytes[i] = Bits2Num(8);
  }
  for (var i = 0; i < 256; i++) {
    dataHashBytes[i \ 8].in[i % 8] <== dataHash[255 - i];
  }


  // Assert the hash is present in the <SignedInfo/Digest> node in the given index
  // Shift left SignedInfo data by given index, base64 decode the first 44 chars, and compare
  // 256 bits = 44 chars when base64 encoded
  component shifter = VarShiftLeft(signedInfoMaxLength, 44);
  shifter.in <== signedInfo;
  shifter.shift <== dataHashIndex;

  component base64Decoder = Base64Decode(32);
  base64Decoder.in <== shifter.out;
  signal dataHashDecoded[32] <== base64Decoder.out;

  for (var i = 0; i < 32; i++) {
    dataHashBytes[31 - i].out === dataHashDecoded[i];
  }


  // Hash <SignedInfo> node (which is what is signed by the RSA private key)
  component signedInfoHasher = Sha1Bytes(signedInfoMaxLength);
  signedInfoHasher.in <== signedInfo;
  signal signedInfoHash[160];
  signedInfoHash <== signedInfoHasher.out;


  // Verify RSA signature with padded SHA1 hash
  component rsa = SHA1RSAVerifier(n, k);
  rsa.sha1Hash <== signedInfoHash;
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
