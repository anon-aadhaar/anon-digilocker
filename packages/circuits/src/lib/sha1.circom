pragma circom 2.1.9;

include "sha1-circom/circuits/sha1.circom";
include "circomlib/circuits/bitify.circom";
include "@zk-email/circuits/lib/rsa.circom";


template Sha1Bytes(maxByteLength) {
  signal input in[maxByteLength];
  signal output out[160];

  var maxBits = maxByteLength * 8;
  component sha = Sha1(maxBits);

  component bytes[maxByteLength];
  for (var i = 0; i < maxByteLength; i++) {
    bytes[i] = Num2Bits(8);
    bytes[i].in <== in[i];

    for (var j = 0; j < 8; j++) {
      sha.in[i * 8 + j] <== bytes[i].out[7 - j];
    }
  }

  for (var i = 0; i < 160; i++) {
    out[i] <== sha.out[i];
  }
}


template SHA1RSAPad(n) {
  var paddedLength = (2048 + n) \ n;

  signal input in[160];
  signal output out[paddedLength];

  // Pad SHA1 hash as input to RSA as per ASN1
  // [0x00, 0x01, 0xff...(218 times), 0x00, 0x3021300906052b0e03021a05000414 (15bytes), SHA1hash (20bytes)]
  // Note: We are only considering 2048 bit keys
  component bitToNums[paddedLength];

  for (var i = 0; i < paddedLength; i++) {
    bitToNums[i] = Bits2Num(n);
  }

  var ASN1_PREFIX_SHA1 = 249903374471035965343514536750089236;
  signal asn1Prefix[120] <== Num2Bits(120)(ASN1_PREFIX_SHA1);

  for (var i = 0; i < n * paddedLength; i++) {
    // Set SHA1 output to the first 20 bytes
    if (i < 20 * 8) {
      bitToNums[i \ n].in[i % n] <== in[(20 * 8 - 1) - i];
    }

    // Set next 15 bytes to ASN1_PREFIX_SHA1
    if (i >= 20 * 8 && i < 35 * 8) {
      bitToNums[i \ n].in[i % n] <== asn1Prefix[i - (20 * 8)];
    }

    // Set next byte to 0x00
    if (i >= 35 * 8 && i < 36 * 8) {
      bitToNums[i \ n].in[i % n] <== 0;
    }

    // Set the next 218 bytes to 0xff
    if (i >= 36 * 8 && i < 254 * 8) {
      bitToNums[i \ n].in[i % n] <== 1;
    }

    // Set the next bytes to [0x00, 0x01] 
    if (i == 254 * 8) {
      bitToNums[i \ n].in[i % n] <== 1;
    }
    if (i > 254 * 8 && i < 256 * 8) {
      bitToNums[i \ n].in[i % n] <== 0;
    }

    // Set remaining bits to 0 for Num2Bits
    if (i >= 256 * 8) {
      bitToNums[i \ n].in[i % n] <== 0;
    }
  }

  for (var i = 0; i < paddedLength; i++) {
    out[i] <== bitToNums[i].out;
  }
}


// Based on https://github.com/zkemail/zk-email-verify/blob/main/packages/circuits/lib/rsa.circom
template SHA1RSAVerifier(n, k) {
  signal input sha1Hash[160];
  signal input signature[k];
  signal input modulus[k];

  // Pad the SHA1 hash as per ASN1
  component shaPadder = SHA1RSAPad(n);
  shaPadder.in <== sha1Hash;

  // Check that the signature is in proper form and reduced mod modulus.
  component signatureRangeCheck[k];
  component bigLessThan = BigLessThan(n, k);
  for (var i = 0; i < k; i++) {
      signatureRangeCheck[i] = Num2Bits(n);
      signatureRangeCheck[i].in <== signature[i];
      bigLessThan.a[i] <== signature[i];
      bigLessThan.b[i] <== modulus[i];
  }
  bigLessThan.out === 1;

  component bigPow = FpPow65537Mod(n, k);
  for (var i = 0; i < k; i++) {
      bigPow.base[i] <== signature[i];
      bigPow.modulus[i] <== modulus[i];
  }

  for (var i = 0; i < k; i++) {
      bigPow.out[i] === shaPadder.out[i];
  }
}
