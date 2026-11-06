
Power dynamics and systems needed in social media is mostly

- Access control list
- Argument of value
    - Argument of non-malice
    - Argument of preference
- Value assignment matrix


## Discrete sources

One of the troubles in a reputational system is that worthy evidence of reputation comes from highly discrete sources, in the form of signed statements from various human authors, automatic hardwares, anything that can sign. 

Discrete is, typically in the form of 256bit publickeys. Informally, known as authors and their signed statements. 

The user values his attention, and wants proof of abuse (against spammers), non-malice (against predators) for his DM list. The user only knows limited amount of trustworthy friends (authors of signed statements). Hence, he has a small value assignment matrix.

The applicant proves to user that he is worthy of the attention through ZKP using signed statements against the matrix.

## Adaptors

Each author has a publickey, and can publish signed statements. 

An adaptor is one kind of the statements. 

It allows a set of other value judgements to be converted to a value, meaningful when only this author is trusted.

*Evidence* is ultimate source of trust, and it is always a signed statement. 

The prover combines evidence, any number of adpators, until the graph reaches what he wants to prove trust to. 

## Logic: MAX(x, y)

In fuzzy logic, `OR` takes `max(x,y)`, which corresponds to that prover can simply choose graph path that has maximal value.

## Impl: Adaptor

An author signs an adaptor

```yaml
- Input: vector of trust values from various authors
    - any other arguments necessary to construct the function
- Output: trust values given by this author
```

The prover can run the program in non-ZK mode to get a result fast. 

In ZK-mode, the execution produces a proof.

## Trust values

What should we use to represent a trust value for author A about B? One scalar?

Perhaps $f:v^{128} \rightarrow n$ where $v$ is an embedding vector, where $v$ is sparse, which leads to compact storage formats.

Perhaps one vector, where each dimension is user's trustworthiness for a level of activity. $v[n]$ denotes user's reputation for activity requiring $n$ level of trust. This makes it quantizable to low dimensions, while generalizable to many different activities. 

In a simple and domain specific case, we consider a pre-agreed feature vector.

- Non-abuse of network services
- Amount of financial/dev contribution to network infrastructure
- Non predatory socially

## State handling

Each signed statement is treated as a static object that may interact with each other or generate new objects through adaptors. 

The system is naturally stateless. Things do not expire. 

State update is de facto done through that verifiers update their set of *acceptable evidence*.

Authors publish new signed statements regularly, and time isn't an inherent concept in this system.

There may be a special kind of adaptors that convert stale evidence to new evidence. 