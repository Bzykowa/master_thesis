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
    function commit(uint256 k, uint256 l, Curve.G1Point memory H) internal view returns (Curve.G1Point memory c) {
        // Generate right point l * H
        Curve.G1Point memory rt = Curve.g1mul(H, l);

        // Generate left point m * g
        Curve.G1Point memory lt = Curve.g1mul(Curve.P1(), k);

        // Generate C = k * G + l * H
        c = Curve.g1add(lt, rt);

        return c;
    }

    
    /**
     * @dev        Verify a Pedersen commitment
     * @param      commitment  The commitment
     * @param      H           Generator H
     * @param      X           First part of a Schnorr signature
     * @param      l           Exponent l
     * @return     res         Success or failure
     */
    function verify(Curve.G1Point memory commitment, Curve.G1Point memory H, Curve.G1Point memory X, uint256 l) internal view returns(bool res) {
        // Generate right point l * H
        Curve.G1Point memory rt = Curve.g1mul(H, l);

        // Generate C = X + l * H
        Curve.G1Point memory c = Curve.g1add(X, rt);

        res = (c.X == commitment.X && c.Y == commitment.Y);
    }
    
}