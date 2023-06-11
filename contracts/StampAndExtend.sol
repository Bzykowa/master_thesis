// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;
import "contracts/libraries/Curve.sol";
import "contracts/libraries/Schnorr.sol";

// Partial implementation of Stamp and Extend scheme: https://eprint.iacr.org/2013/730.pdf
contract TSA {
    // Stored public data
    struct TimeStampEntry {
        Curve.G1Point X;
        uint256 s;
        uint256 l;
        uint256 i;
        uint256 data;
    }
    // Record of issued timestamps
    TimeStampEntry[] public HS;
    // Record of existing commitments
    Curve.G1Point[] public C;
    // The public key of TSA
    Curve.G1Point public pubKey;
    // The generator h
    Curve.G1Point public H;
    // Data waiting to be timestamped
    mapping(address => uint256) public pendingTimeStamps;
    address[] private pendingIndexes;
    // Addresses allowed to publish a timestamp
    mapping(address => bool) internal issuers;

    // Events
    event TimeStampRequested(address requester, uint256 data);
    event TimeStampIssued(address requester, TimeStampEntry timestamp);

    constructor(
        uint256[2] memory pkey,
        uint256[2] memory h,
        uint256[2] memory c1,
        uint256[6] memory hs0
    ) {
        pubKey = Curve.G1Point(pkey[0], pkey[1]);
        H = Curve.G1Point(h[0], h[1]);
        C.push(Curve.G1Point(c1[0], c1[1]));
        HS.push(
            TimeStampEntry(
                Curve.G1Point(hs0[0], hs0[1]),
                hs0[2],
                hs0[3],
                hs0[4],
                hs0[5]
            )
        );
        issuers[msg.sender] = true;
    }

    // Getters

    function getHS() external view returns (TimeStampEntry[] memory) {
        return HS;
    }

    function getC() external view returns (Curve.G1Point[] memory) {
        return C;
    }

    function getPendingData()
        external
        view
        returns (address[] memory requesters, uint256[] memory data)
    {
        requesters = pendingIndexes;
        data = new uint256[](requesters.length);
        for (uint256 i = 0; i < requesters.length; i++) {
            data[i] = pendingTimeStamps[requesters[i]];
        }
    }

    // Request a timestamp
    function requestTimeStamp(uint256 data) external {
        require(
            pendingTimeStamps[msg.sender] == 0,
            "You already requested a timestamp!"
        );
        pendingTimeStamps[msg.sender] = data;
        pendingIndexes.push(msg.sender);
        emit TimeStampRequested(msg.sender, data);
    }

    // Issue a timestamp
    function issueTimeStamp(
        uint256[6] memory ti,
        uint256[4] memory comms,
        address requester
    ) external {
        require(issuers[msg.sender], "Only approved accounts allowed!");
        require(
            pendingTimeStamps[msg.sender] != 0,
            "This person didn't request a timestamp!"
        );
        // Extend HS
        TimeStampEntry memory HSi = TimeStampEntry(
            Curve.G1Point(ti[0], ti[1]),
            ti[2],
            ti[3],
            ti[4],
            ti[5]
        );
        HS.push(HSi);
        // Extend C with c_2i,c_2i+1
        C.push(Curve.G1Point(comms[0], comms[1]));
        C.push(Curve.G1Point(comms[2], comms[3]));
        // Let the requester know that timestamp has been issued
        emit TimeStampIssued(requester, HSi);
        // Delete address from pending record
        delete pendingTimeStamps[requester];
        address[] memory _requesters = pendingIndexes;
        for (uint256 i = 0; i < _requesters.length; i++) {
            if (_requesters[i] == requester) {
                pendingIndexes[i] = _requesters[_requesters.length - 1];
                pendingIndexes.pop();
                break;
            }
        }
    }

    // Binary logarithm floored
    function log2floor(uint256 x) internal pure returns (uint256 n) {
        require(x > 0, "Log_2 x only for x > 0.");
        if (x >= 2**128) {
            x >>= 128;
            n += 128;
        }
        if (x >= 2**64) {
            x >>= 64;
            n += 64;
        }
        if (x >= 2**32) {
            x >>= 32;
            n += 32;
        }
        if (x >= 2**16) {
            x >>= 16;
            n += 16;
        }
        if (x >= 2**8) {
            x >>= 8;
            n += 8;
        }
        if (x >= 2**4) {
            x >>= 4;
            n += 4;
        }
        if (x >= 2**2) {
            x >>= 2;
            n += 2;
        }
        if (x >= 2) {
            /* x >>= 1; */
            n += 1;
        }
    }

    // Verify the i-th timestamp
    function verifyTimeStamp(uint256 i) external view returns (bool valid) {
        require(i >= 1, "Accepting only i >= 1.");
        TimeStampEntry[] memory _HS = HS;
        require(i < _HS.length, "We haven't issued this timestamp yet.");
        Curve.G1Point[] memory _C = C;
        uint256[2] memory pk = [pubKey.X, pubKey.Y];
        Curve.G1Point memory _H = H;

        for (uint256 alpha = 0; alpha <= log2floor(i); alpha++) {
            uint256 j = i / (2**alpha);
            // Hash j-1-th timestamp
            uint256 hs1 = uint256(
                keccak256(
                    abi.encodePacked(
                        _HS[j - 1].X.X,
                        _HS[j - 1].X.Y,
                        _HS[j - 1].s,
                        _HS[j - 1].l,
                        _HS[j - 1].i,
                        _HS[j - 1].data
                    )
                )
            );
            // Reconstruct message
            uint256 m = uint256(
                keccak256(
                    abi.encodePacked(
                        hs1,
                        _HS[j].data,
                        _C[2 * j - 1].X,
                        _C[2 * j - 1].Y,
                        _C[2 * j].X,
                        _C[2 * j].Y,
                        _HS[j].l,
                        _HS[j].i
                    )
                )
            );
            uint256[2] memory x = [_HS[j].X.X, _HS[j].X.Y];
            bool proof = Schnorr.VerifyProof(pk, m, x, _HS[j].s);
            Curve.G1Point memory c_j = Curve.g1add(
                _HS[j].X,
                Curve.g1mul(_H, _HS[j].l)
            );
            if (!proof || c_j.X != _C[j - 1].X || c_j.Y != _C[j - 1].Y) {
                return false;
            }
        }
        uint256 cert_m = uint256(
            keccak256(abi.encodePacked(pk[0], pk[1], _C[0].X, _C[0].Y))
        );
        uint256[2] memory xx = [_HS[0].X.X, _HS[0].X.Y];
        return Schnorr.VerifyProof(pk, cert_m, xx, _HS[0].s);
    }

    // Set issuer info (true - can make ts, false - can't)
    function setIssuer(address issuer, bool rights) external {
        require(issuers[msg.sender], "Only approved accounts allowed!");
        issuers[issuer] = rights;
    }
}
