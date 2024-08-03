pragma circom 2.1.9;

include "./digilocker-verifier-template.circom";

// 512 * 3 should be increased is the data after <CertificateData> is larger
component main { public [nullifierSeed, signalHash] } = DigiLockerVerifierTemplate(121, 17, 512 * 3);
