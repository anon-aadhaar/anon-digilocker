pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "../helpers/constants.circom";


/// @title Nullifier
/// @notice Computes the nullifier for an Aadhaar identity
/// @input photo The photo of the user with SHA padding
/// @output nullifier = hash(nullifierSeed, hash(photo[0:15]), hash(photo[16:31]))
template Nullifier() {
    signal input nullifierSeed;
    signal input precomputedSHA[32];

    signal output out;

    // Assert precomputedSHA is set
    var sum = 0;
    for (var i = 0; i < 32; i++) {
        sum = sum + precomputedSHA[i];
    }
    signal isSHAZero <== IsZero()(sum);
    isSHAZero === 0;

    // Poseidon template only support 16 inputs - so we do in two chunks (photo is 32 chunks)
    component first16Hasher = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        first16Hasher.inputs[i] <== precomputedSHA[i];
    }

    component last16Hasher = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        last16Hasher.inputs[i] <== precomputedSHA[i + 16];
    }

    out <== Poseidon(3)([nullifierSeed, first16Hasher.out, last16Hasher.out]);
}
