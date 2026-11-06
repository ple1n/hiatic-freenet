
Consensus is not modelled as a BFT formulation. 

Imagine a network of nodes, each with a state machine, the machine holds an initial mapping of nodes $\rightarrow$ voting power, an initial mapping of key $\rightarrow$ value state.

Nodes are allowed to gossip, and the state machine ingests new delta, and transmits updates to other nodes as it sees fit.

Regardless of low-level data structure, the state machine can be represented as a directed acyclic graph, where edge direction is established by hash chaining, as an absolute evidence of 'constructed before'.

The ends of this DAG are called tips. It is generally convergent when nodes pick for the tip with highest accumulated voting weight.

This entire thing can be expressed in SP1.

This part is not needed for most function of the app.