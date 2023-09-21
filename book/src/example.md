# Example

## Install

```bash
cargo install mdbook
cargo install mdbook-mermaid
cargo install mdbook-linkcheck
```

## Reference code with ANCHOR

```
// ANCHOR: events
```

```rust,no_run,no_playground
{{#include ../../contracts/multisig/src/events.rs:events}}
```

```
// ANCHOR_END: events
```

Note: [Include directives to missing files do not return error](https://github.com/rust-lang/mdBook/issues/1094)

## Mermaid diagram

```mermaid
flowchart TD
subgraph Axelar
	G1{"Gateway"}
    G2{"Gateway"}
	Vr{"Aggregate Verifier"}
	Vo{"Voting verifier"}
	R{"Router"}
    S{"Service Registry"}
end

Relayer --"VerifyMessages([M1,M2])"-->G1
G1 --"VerifyMessages([M1,M2])"--> Vr
Vr --"VerifyMessages([M1,M2])"--> Vo
Vo --"GetActiveWorkers"--> S
Workers --"Vote(poll_id, votes)"--> Vo

Relayer --"RouteMessages([M1,M2])"-->G1
G1 --"RouteMessages([M1,M2])"-->R
R --"RouteMessages([M1,M2])"-->G2
```
