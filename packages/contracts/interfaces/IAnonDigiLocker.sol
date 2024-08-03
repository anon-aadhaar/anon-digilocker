// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;

interface IAnonDigiLocker {
    function verifyAnonDigiLockerProof(
        uint nullifierSeed,
        uint nullifier,
        uint documentType,
        uint reveal,
        uint signal,
        uint[8] memory groth16Proof
    ) external view returns (bool);
}
