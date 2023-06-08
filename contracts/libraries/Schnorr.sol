// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./Curve.sol";

// https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol
library Schnorr {
    // Modified Schnorr Signature to use in Stamp and Extend with updated notation
    function CreateProof(
        uint256 secret_key,
        uint256 message,
        uint256 k
    )
        internal
        view
        returns (
            uint256[2] memory out_pubkey,
            uint256[2] memory X,
            uint256 s
        )
    {
        Curve.G1Point memory A = Curve.g1mul(
            Curve.P1(),
            secret_key % Curve.N()
        );
        out_pubkey[0] = A.X;
        out_pubkey[1] = A.Y;
        uint256 x = k % Curve.N();
        Curve.G1Point memory XX = Curve.g1mul(Curve.P1(), x);
        X[0] = XX.X;
        X[1] = XX.Y;
        uint256 h = uint256(keccak256(abi.encodePacked(X[0], X[1], message)));
        s = addmod(x, mulmod(secret_key, h, Curve.N()), Curve.N());
    }

    // Calculates proof of a Schnorr signature with updated notation
    function CalcProof(
        uint256[2] memory pubkey,
        uint256 message,
        uint256[2] memory X
    ) internal view returns (uint256[2] memory s) {
        uint256 h = uint256(keccak256(abi.encodePacked(X[0], X[1], message)));
        Curve.G1Point memory A = Curve.G1Point(pubkey[0], pubkey[1]);
        Curve.G1Point memory sG = Curve.g1add(
            Curve.G1Point(X[0], X[1]),
            Curve.g1mul(A, h)
        );
        s[0] = sG.X;
        s[1] = sG.Y;
    }

    function VerifyProof(
        uint256[2] memory pubkey,
        uint256 message,
        uint256[2] memory X,
        uint256 s
    ) internal view returns (bool) {
        Curve.G1Point memory sG = Curve.g1mul(Curve.P1(), s);
        uint256[2] memory proof = CalcProof(pubkey, message, X);
        return sG.X == proof[0] && sG.Y == proof[1];
    }
}
