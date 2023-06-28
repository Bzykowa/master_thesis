# Master thesis

*Topic: Selected cryptographic schemes implemented in the blockchain system*

*Abstract:*
During the last decade, we have observed the rise of the blockchain technology from simple
distributed ledgers to powerful programmable networks. This master thesis aims to explore
the computational capabilities of these systems to implement selected cryptographic schemes.
The work covers the design and implementation of a distributed timestamping system based
on a protocol combining Schnorr signatures and Pedersen commitments in which data is stored
and validated using Ethereum network. The proposed system utilizes a smart contract to store
protocol data and mediate the flow of information between server nodes which issue timestamps
and client nodes who can submit data for timestamping and call the verification procedure on
any recorded timestamp. We evaluate the efficiency of the implemented protocol based on gas
fees, memory usage and execution time. The work discusses the advantages and limitations of
Ethereum network observed during the development of the system, such as the public storage
which on one hand provides full transparency and on the other prevents us from keeping any
secret on the network.
