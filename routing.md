
The main target of routing model is Freenet, a greedy-routed DHT system.

Time complexity

- `O(1)` for known/cached contracts
- `O(log N)` for contracts new to local node, which requires time for lookups.

Room state can be stored in many ways, more centralized or dispersed among Freenet contracts.

- Centralization leads to better look-up dynamics
- Dispersion increases attack-resistance, as it can be designed such that many contract locations are known only to chat participants. 

Freenet is not meant to be used for large file storage, voice calls, etc. 

Rooms are to be rotated as chat log grows

