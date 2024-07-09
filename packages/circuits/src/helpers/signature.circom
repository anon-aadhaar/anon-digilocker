pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "@zk-email/circuits/lib/sha.circom";
include "@zk-email/circuits/lib/rsa.circom";
include "@zk-email/circuits/lib/base64.circom";
include "@zk-email/circuits/utils/array.circom";
// include "./rsa-sha1.circom";
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

  // Assert first 13 elements are <DigestValue>
  // digestValueNode[0] === 0x3c;
  // digestValueNode[1] === 0x44;
  // digestValueNode[2] === 0x69;
  // digestValueNode[3] === 0x67;
  // digestValueNode[4] === 0x65;
  // digestValueNode[5] === 0x73;
  // digestValueNode[6] === 0x74;
  // digestValueNode[7] === 0x56;
  // digestValueNode[8] === 0x61;
  // digestValueNode[9] === 0x6c;
  // digestValueNode[10] === 0x75;
  // digestValueNode[11] === 0x65;

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


  component signedInfoHasher = Sha1Bytes(signedInfoMaxLength);
  signedInfoHasher.in <== signedInfo;
  signal signedInfoHash[160];
  signedInfoHash <== signedInfoHasher.out;


  // Structure for SHA1 input to RSA as per ASN1
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

      // // Set the first byte to 0x00 and second byte to 0x01
    // if (i < 15) {
    //   rsaInput[i \ n].in[i % n] <== 0;
    // }
    // if (i == 15) {
    //   rsaInput[i \ n].in[i % n] <== 1;
    // }

    // // Set the next 218 bytes to 0xff
    // if (i >= 16 && i < (220 * 8)) {
    //   rsaInput[i \ n].in[i % n] <== 1;
    // }

    // // Set the next byte to 0x00
    // if (i >= 220 * 8 && i < 221 * 8) {
    //   rsaInput[i \ n].in[i % n] <== 0;
    // }

    // // Set next 15 bytes to ASN1_PREFIX_SHA1
    // if (i >= 221 * 8 && i < 236 * 8) {
    //   rsaInput[i \ n].in[i % n] <== asn1Prefix[236 * 8 - i - 1];


  // var rsaMsgLength = (160 + n) \ n;
  // component rsaBaseMsg[rsaMsgLength];
  // for (var i = 0; i < rsaMsgLength; i++) {
  //     rsaBaseMsg[i] = Bits2Num(n);
  // }
  // for (var i = 0; i < 160; i++) {
  //     rsaBaseMsg[i \ n].in[i % n] <== signedInfoHash[159 - i];
  // }
  // for (var i = 160; i < n * rsaMsgLength; i++) {
  //     rsaBaseMsg[i \ n].in[i % n] <== 0;
  // }


  component rsa = RSAVerifier65537(n, k);

  for (var i = 0; i < rsaInputLength; i++) {
      rsa.message[i] <== rsaInput[i].out;
  }

  rsa.modulus <== pubKey;
  rsa.signature <== signature;



    // component rsaSha1 = RsaSha1VerifyPkcs1v15(n, k, 17, 3);
    // rsaSha1.sign <== signature;
    // rsaSha1.hashed[0] <== rsaBaseMsg[0].out;
    // rsaSha1.hashed[1] <== rsaBaseMsg[1].out;
    // rsaSha1.hashed[2] <== rsaBaseMsg[2].out;
    // rsaSha1.hashed[3] <== rsaBaseMsg[3].out;
    // rsaSha1.hashed[4] <== rsaBaseMsg[4].out;

    // log(rsaSha1.hashed[0]);
    // log(rsaSha1.hashed[1]);
    // log(rsaSha1.hashed[2]);
    // log(rsaSha1.hashed[3]);
    // log(rsaSha1.hashed[4]);
    
    // rsaSha1.exp <== 65537;
    // rsaSha1.modulus <== pubKey;



  // // Calculate Poseidon hash of the public key (609 constraints)
  // // Poseidon component can take only 16 inputs, so we convert k chunks to k/2 chunks.
  // // We are assuming k is > 16 and <= 32 (i.e we merge two consecutive item in array to bring down the size)
  // var poseidonInputSize = k \ 2;
  // if (k % 2 == 1) {
  //     poseidonInputSize++;
  // }
  // assert(poseidonInputSize <= 16);

  // signal pubkeyHasherInput[poseidonInputSize];
  // for (var i = 0; i < poseidonInputSize; i++) {
  //     if (i == poseidonInputSize - 1 && k % 2 == 1) {
  //         pubkeyHasherInput[i] <== pubKey[i * 2];
  //     } else {
  //         pubkeyHasherInput[i] <== pubKey[i * 2] + (1 << n) * pubKey[i * 2 + 1];
  //     }
  // }
  // component pubkeyHasher = Poseidon(poseidonInputSize);
  // pubkeyHasher.inputs <== pubkeyHasherInput;
  // pubkeyHash <== pubkeyHasher.out;
}
