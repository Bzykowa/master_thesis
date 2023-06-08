// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./Curve.sol";

library Pedersen {
    /**
     * @dev        Generate Pedersen Commitment C = k * G + l * H
     * @param      k         Secret exponent
     * @param      l         Secret exponent
     * @param      H         Generator H
     * @return     c         Pedersen commitment
     */
    function commit(
        uint256 k,
        uint256 l,
        uint256[2] memory H
    ) internal view returns (uint256[2] memory c) {
        // Generate right point l * H
        Curve.G1Point memory rt = Curve.g1mul(Curve.G1Point(H[0], H[1]), l);

        // Generate left point m * g
        Curve.G1Point memory lt = Curve.g1mul(Curve.P1(), k);

        // Generate C = k * G + l * H
        Curve.G1Point memory C = Curve.g1add(lt, rt);
        c[0] = C.X;
        c[1] = C.Y;
    }

    /**
     * @dev        Verify a Pedersen commitment
     * @param      commitment  The commitment
     * @param      H           Generator H
     * @param      X           First part of a Schnorr signature
     * @param      l           Exponent l
     * @return     res         Success or failure
     */
    function verify(
        uint256[2] memory commitment,
        uint256[2] memory H,
        uint256[2] memory X,
        uint256 l
    ) internal view returns (bool res) {
        // Generate right point l * H
        Curve.G1Point memory rt = Curve.g1mul(Curve.G1Point(H[0], H[1]), l);

        // Generate C = X + l * H
        Curve.G1Point memory c = Curve.g1add(Curve.G1Point(X[0], X[1]), rt);

        res = (c.X == commitment[0] && c.Y == commitment[1]);
    }
}
