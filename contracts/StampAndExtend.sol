// SPDX-License-Identifier: MIT

pragma solidity ^0.8.18;
import "./libraries/Curve.sol";

contract TSA {
    // Stored public data
    struct TimeStampEntry {
        Curve.G1Point X;
        uint256 s;
        uint256 l;
        uint256 i;
        uint256 data;
    }
    TimeStampEntry[] public HS;
    Curve.G1Point[] public C;
    Curve.G1Point public pubKey;
    mapping(address => uint256) private pendingTimeStamps;
    mapping(address => bool) internal issuers;

    // Events
    event TimeStampRequested(address requester, uint256 data);
    event TimeStampIssued(address requester, TimeStampEntry timestamp);

    // Errors
    error NotApprovedToIssueTimeStamps(address sender);

    constructor(
        uint256[2] memory pkey,
        uint256[2] memory c1,
        uint256[6] memory hs0
    ) {
        pubKey = Curve.G1Point(pkey[0], pkey[1]);
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

    function getHS() public view returns (TimeStampEntry[] memory) {
        return HS;
    }

    function getC() public view returns (Curve.G1Point[] memory) {
        return C;
    }

    function getPubKey() public view returns (Curve.G1Point memory) {
        return pubKey;
    }

    // Request a timestamp
    function requestTimeStamp(uint256 data) external {
        pendingTimeStamps[msg.sender] = data;
        emit TimeStampRequested(msg.sender, data);
    }

    // Issue a timestamp
    function issueTimeStamp(
        uint256[6] memory ti,
        uint256[4] memory comms,
        address requester
    ) external {
        require(issuers[msg.sender]);
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
        // Let the requester know that timestamp is issued
        emit TimeStampIssued(requester, HSi);
        delete pendingTimeStamps[requester];
    }

    // Verify the i-th timestamp
    function verifyTimeStamp(uint256 i) external view returns (bool valid) {}
}

//Only the public lists HS and C, pk A - done

//Implement the read operations for HS,C,A for anyone - done

//Implement events for communication with TSA (TimestampRequested,TimestampIssued) - done

//Implement write operations to HS and C for a trusted party - done

//Implement a submission of a value to be timestamped - done

//Implement a verification algorithm for a timestamp
