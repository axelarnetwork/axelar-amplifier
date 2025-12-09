# Changelog

## [Unreleased](https://github.com/axelarnetwork/axelar-amplifier/tree/HEAD)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.12.2..HEAD)

## [v1.12.2](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.12.2) (2025-10-03)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.12.1..ampd-v1.12.2)

- add cancellation token to confirmer and broadcaster [#1056](https://github.com/axelarnetwork/axelar-amplifier/pull/1056)
- add name to task runs [#1055](https://github.com/axelarnetwork/axelar-amplifier/pull/1055)
- rotate out blastapi rpcs [#1054](https://github.com/axelarnetwork/axelar-amplifier/pull/1054)

## [v1.12.1](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.12.1) (2025-09-25)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.12.0..ampd-v1.12.1)

- add event filtering to event handlers [#1049](https://github.com/axelarnetwork/axelar-amplifier/pull/1049)

## [v1.12.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.12.0) (2025-09-19)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.11.0..ampd-v1.12.0)

- retry when there is a sequence mismatch error [#1042](https://github.com/axelarnetwork/axelar-amplifier/pull/1042)
- add latest block height method to grpc server [#1040](https://github.com/axelarnetwork/axelar-amplifier/pull/1040)
- deserialize cosmrs message values [#1032](https://github.com/axelarnetwork/axelar-amplifier/pull/1032)
- add config module [#1022](https://github.com/axelarnetwork/axelar-amplifier/pull/1022)
- fix compilation error when not using `dummy-grpc-broadcast` [#1030](https://github.com/axelarnetwork/axelar-amplifier/pull/1030)
- setup message logger for evm handler [#1026](https://github.com/axelarnetwork/axelar-amplifier/pull/1026)
- implement blockchain service method `contracts` [#1009](https://github.com/axelarnetwork/axelar-amplifier/pull/1009)
- move hardcoded values into config [#1019](https://github.com/axelarnetwork/axelar-amplifier/pull/1019)
- miscellaneous changes to add `router_api` macros to tests [#1004](https://github.com/axelarnetwork/axelar-amplifier/pull/1004)
- track ampd error in monitoring server [#998](https://github.com/axelarnetwork/axelar-amplifier/pull/998)
- ampd release doc update [#1012](https://github.com/axelarnetwork/axelar-amplifier/pull/1012)
- add custom linter to basic workflow [#981](https://github.com/axelarnetwork/axelar-amplifier/pull/981)
- record stage metrics in monitoring server [#985](https://github.com/axelarnetwork/axelar-amplifier/pull/985)
- track error returns by rpc nodes [#973](https://github.com/axelarnetwork/axelar-amplifier/pull/973)

## [v1.11.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.11.0) (2025-08-14)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.10.0..ampd-v1.11.0)

- stellar protocol v23 update [#968](https://github.com/axelarnetwork/axelar-amplifier/pull/968)
- use `address!` macro instead of string literal conversion [#996](https://github.com/axelarnetwork/axelar-amplifier/pull/996)
- use `chain_name!` macro instead of string literal conversion [#992](https://github.com/axelarnetwork/axelar-amplifier/pull/992)
- use `chain_name_raw!` macro instead of string literal conversion [#993](https://github.com/axelarnetwork/axelar-amplifier/pull/993)
- reset sequence number before enqueuing message for broadcast [#994](https://github.com/axelarnetwork/axelar-amplifier/pull/994)
- add ampd cpu and memory usage metrics tracking [#965](https://github.com/axelarnetwork/axelar-amplifier/pull/965)
- track vote verification outcome in voting handler [#959](https://github.com/axelarnetwork/axelar-amplifier/pull/959)
- unify Rust setup across workflows [#987](https://github.com/axelarnetwork/axelar-amplifier/pull/987)

## [v1.10.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.10.0) (2025-07-28)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.9.0..ampd-v1.10.0)

- add stacks handlers [#728](https://github.com/axelarnetwork/axelar-amplifier/pull/728)
- use cargo chef for internal dependencies [#967](https://github.com/axelarnetwork/axelar-amplifier/pull/967)
- add tx confirmation when executing commands [#961](https://github.com/axelarnetwork/axelar-amplifier/pull/961)
- add security audit configuration and workflow [#946](https://github.com/axelarnetwork/axelar-amplifier/pull/946)
- replace broadcaster with v2 [#836](https://github.com/axelarnetwork/axelar-amplifier/pull/836)
- prevent port collisions in monitoring server tests [#954](https://github.com/axelarnetwork/axelar-amplifier/pull/954)
- replace prometheus crate with official prometheus_client crate [#950](https://github.com/axelarnetwork/axelar-amplifier/pull/950)
- streamline monitoring module structure [#938](https://github.com/axelarnetwork/axelar-amplifier/pull/938)
- implement crypto service method key [#861](https://github.com/axelarnetwork/axelar-amplifier/pull/861)
- use custom streams to improve readability of the event stream implementation [#921](https://github.com/axelarnetwork/axelar-amplifier/pull/921)
- modularize monitoring server and add configurability [#927](https://github.com/axelarnetwork/axelar-amplifier/pull/927)
- add feature flags for url, config, and commands [#936](https://github.com/axelarnetwork/axelar-amplifier/pull/936)
- add a prometheus client to track metrics in ampd [#897](https://github.com/axelarnetwork/axelar-amplifier/pull/897)
- do not use redacted string when initializing HttpClient [#922](https://github.com/axelarnetwork/axelar-amplifier/pull/922)
- add support for sensitivity and redacted logging [#920](https://github.com/axelarnetwork/axelar-amplifier/pull/920)
- integrate span traces for fns that create LoggableError explicitly (except event_processor.rs) [#914](https://github.com/axelarnetwork/axelar-amplifier/pull/914)
- handle RPC and other handler errors gracefully at startup [#916](https://github.com/axelarnetwork/axelar-amplifier/pull/916)
- enable detailed span tracing for LoggableError [#913](https://github.com/axelarnetwork/axelar-amplifier/pull/913)
- expose derive macros via feature flag [#902](https://github.com/axelarnetwork/axelar-amplifier/pull/902)
- add eol normalization [#907](https://github.com/axelarnetwork/axelar-amplifier/pull/907)

## [v1.9.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.9.0) (2025-06-04)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.8.0..ampd-v1.9.0)

- Add configurable delay before block processing [#860](https://github.com/axelarnetwork/axelar-amplifier/pull/860)
- Add curl and wget to ampd dockerfile [#887](https://github.com/axelarnetwork/axelar-amplifier/pull/887)
- Make gRPC related errors transparent [#870](https://github.com/axelarnetwork/axelar-amplifier/pull/870)

## [v1.8.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.8.0) (2025-05-16)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.7.0..ampd-v1.8.0)

- Change XRPL handler to listen to multisig contract [#850](https://github.com/axelarnetwork/axelar-amplifier/pull/850)

## [v1.7.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.7.0) (2025-04-07)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.6.0..ampd-v1.7.0)

- Add Solana support to ampd [#744](https://github.com/axelarnetwork/axelar-amplifier/pull/744)
- Fix parsing of non-standard XRPL currencies [#797](https://github.com/axelarnetwork/axelar-amplifier/pull/797)

## [v1.6.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.6.0) (2025-04-02)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.1..ampd-v1.6.0)

- Separate multisig config per chain [#772](https://github.com/axelarnetwork/axelar-amplifier/pull/772) and [#790](https://github.com/axelarnetwork/axelar-amplifier/pull/790)
- Refactor event sub to support gRPC subscribe [#777](https://github.com/axelarnetwork/axelar-amplifier/pull/777)
- Make chain names case insensitive in ampd verification [#785](https://github.com/axelarnetwork/axelar-amplifier/pull/785) and [#787](https://github.com/axelarnetwork/axelar-amplifier/pull/787)
- Use case sensitive destination chain in XRPL gateway and verifier [#788](https://github.com/axelarnetwork/axelar-amplifier/pull/788)
- Fix expected format for non-standard XRPL currencies [#789](https://github.com/axelarnetwork/axelar-amplifier/pull/789)

## [v1.5.1](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.5.1) (2025-03-26)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.5.0..ampd-v1.5.1)

- Fix arithmetic operations with XRPLTokenAmount [#780](https://github.com/axelarnetwork/axelar-amplifier/pull/780)

## [v1.5.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.5.0) (2025-03-24)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.4.0..ampd-v1.5.0)

- Add support for Starknet GMP [#731](https://github.com/axelarnetwork/axelar-amplifier/pull/731)
- Add support for XRPL GMP and token transfers [#764](https://github.com/axelarnetwork/axelar-amplifier/pull/764)
- Ignore fee estimation failures [#767](https://github.com/axelarnetwork/axelar-amplifier/pull/767)

## [v1.4.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.4.0) (2024-12-12)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.3.0..ampd-v1.4.0)

- Update sui dependencies to fix RPC issue [#721](https://github.com/axelarnetwork/axelar-amplifier/pull/721)
- Add support for Bech32m message id format [#689](https://github.com/axelarnetwork/axelar-amplifier/pull/689)
- Add Router migration to delete chains [#710](https://github.com/axelarnetwork/axelar-amplifier/pull/710)

## [v1.3.0](https://github.com/axelarnetwork/axelar-amplifier/tree/ampd-v1.3.0) (2024-11-19)

[Full Changelog](https://github.com/axelarnetwork/axelar-amplifier/compare/ampd-v1.2.0..ampd-v1.3.0)

- Change event index in message ids from u32 to u64. Emit message id from voting verifier [#666](https://github.com/axelarnetwork/axelar-amplifier/pull/666)
- Ampd switch from horizon to RPC client for Stellar verifier [#694](https://github.com/axelarnetwork/axelar-amplifier/pull/694)

#### Migration Notes

Upgrade or deploy contracts/components in the below order:

##### Contracts that should be deployed fresh

- interchain-token-service
- axelarnet-gateway (deploy with chain name "axelar")

##### Contracts that need migration

- coordinator
- gateway
- rewards
- router
- multisig
- multisig-prover
- service-registry
- voting-verifier

##### Components that need upgrading

- ampd

##### Contracts no longer used (no longer part of the active system)

- nexus-gateway

The voting verifier contracts must be migrated before ampd is upgraded. Existing ampd instances will continue to work even after the contract migration, but we recommend upgrading ampd.
