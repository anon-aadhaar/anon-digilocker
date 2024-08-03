pragma circom 2.1.9;

include "./digilocker-verifier-template.circom";

// 64 * 20 should be increased is the data after <CertificateData> is larger
component main = DigiLockerVerifierTemplate(121, 17, 64 * 20);
