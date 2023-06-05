// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./Curve.sol";

// https://en.wikipedia.org/wiki/Proof_of_knowledge#Schnorr_protocol
library Schnorr
{
    // Modified Schnorr Signature to use in Stamp and Extend with updated notation
	function CreateProof( uint256 secret_key, uint256 message, uint256 k)
	    view internal
	    returns (uint256[2] memory out_pubkey, Curve.G1Point memory X, uint256 s)
	{
		Curve.G1Point memory A = Curve.g1mul(Curve.P1(), secret_key % Curve.N());
		out_pubkey[0] = A.X;
		out_pubkey[1] = A.Y;
		uint256 x = k % Curve.N();
		X = Curve.g1mul(Curve.P1(), x);
		uint256 h = uint256(keccak256(abi.encodePacked(X.X, X.Y, message)));
		s = addmod(x, mulmod(secret_key, h, Curve.N()), Curve.N());
	}

	// Calculates proof of a Schnorr signature with updated notation
	function CalcProof( uint256[2] memory pubkey, uint256 message, Curve.G1Point memory X)
	    view internal
	    returns (Curve.G1Point memory sG)
	{
		uint256 h = uint256(keccak256(abi.encodePacked(X.X, X.Y, message)));
	    Curve.G1Point memory A = Curve.G1Point(pubkey[0], pubkey[1]);
	    sG = Curve.g1add(X, Curve.g1mul(A, h));
	}
	
	function VerifyProof( uint256[2] memory pubkey, uint256 message, Curve.G1Point memory X, uint256 s)
	    view internal
	    returns (bool)
	{
		Curve.G1Point memory sG = Curve.g1mul(Curve.P1(), s);
		Curve.G1Point memory proof = CalcProof(pubkey, message, X);
	    return sG.X == proof.X && sG.Y == proof.Y;
	}
}