pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/base64.circom";
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


  // Pad SHA1 hash as input to RSA as per ASN1
  // [0x00, 0x01, 0xff...(218 times), 0x00, 0x3021300906052b0e03021a05000414 (15bytes), SHA1hash (20bytes)]
  // Note: We are only considering 2048 bit keys
  var rsaInputLength = (2048 + n) \ n;
  component rsaInput[rsaInputLength];
  
  for (var i = 0; i < rsaInputLength; i++) {
      rsaInput[i] = Bits2Num(n);
  }

  var ASN1_PREFIX_SHA1 = 249903374471035965343514536750089236;
  signal asn1Prefix[120] <== Num2Bits(120)(ASN1_PREFIX_SHA1);

  for (var i = 0; i < n * rsaInputLength; i++) {
    // Set SHA1 output to the first 20 bytes
    if (i < 20 * 8) {
      rsaInput[i \ n].in[i % n] <== signedInfoHash[(20 * 8 - 1) - i];
    }

    // Set next 15 bytes to ASN1_PREFIX_SHA1
    if (i >= 20 * 8 && i < 35 * 8) {
      rsaInput[i \ n].in[i % n] <== asn1Prefix[i - (20 * 8)];
    }

    // Set next byte to 0x00
    if (i >= 35 * 8 && i < 36 * 8) {
      rsaInput[i \ n].in[i % n] <== 0;
    }

    // Set the next 218 bytes to 0xff
    if (i >= 36 * 8 && i < 254 * 8) {
      rsaInput[i \ n].in[i % n] <== 1;
    }

    // Set the next bytes to [0x00, 0x01] 
    if (i == 254 * 8) {
      rsaInput[i \ n].in[i % n] <== 1;
    }
    if (i > 254 * 8 && i < 256 * 8) {
      rsaInput[i \ n].in[i % n] <== 0;
    }

    // Set remaining bits to 0 for Num2Bits
    if (i >= 256 * 8) {
      rsaInput[i \ n].in[i % n] <== 0;
    }
  }

  // Verify RSA signature with padded SHA1 hash
  component rsa = RSAVerifier65537(n, k);

  for (var i = 0; i < rsaInputLength; i++) {
      rsa.message[i] <== rsaInput[i].out;
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
