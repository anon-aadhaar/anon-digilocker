pragma circom 2.1.9;

include "sha1-circom/circuits/sha1.circom";
include "circomlib/circuits/bitify.circom";


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
