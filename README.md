# OpencodeContract

OpencodeContract is the machine-readable shared contract for canonical OpenCode roles, models, availability invariants, optional compatibility extensions, and consumer conformance for the OpenCode configurations implemented by [`upiscium/dotnix`](https://github.com/upiscium/dotnix) and [`upiscium/Templates`](https://github.com/upiscium/Templates).

> **OpencodeContract does not own the complete OpenCode configuration.**
>
> **It owns shared policy and compatibility contracts.**

`dotnix` and `Templates` remain implementation owners of their respective profiles. This repository is deliberately not a third OpenCode configuration implementation, a file-copy source, or an Agent Core consumer.

## Why this repository exists

The two consumers share role names, fixed model identities, model-availability behavior, and durable safety constraints, while retaining materially different authority and lifecycle semantics. Keeping those contracts only in implementation files makes intentional differences hard to distinguish from drift. OpencodeContract provides one reviewable source of truth above both implementations without moving either implementation here.

```text
OpencodeContract
    | shared policy / compatibility contract
    +----------------------+----------------------+
    v                                             v
dotnix global profile                     Templates Agent-Core profile
    v                                             v
~/.config/opencode                        repository-local Agent Core
```

There is no dependency from OpencodeContract to Templates Agent Core generation or adoption. This repository must remain independently bootstrapped so that `OpencodeContract -> Templates -> OpencodeContract` cannot arise.

## Ownership boundary

### dotnix owns

- the global generic-repository implementation;
- user/provider credentials and provider configuration;
- Ollama endpoints and models;
- TUI and user or machine preferences;
- global permissions, commands, skills, and complete global agent prompts.

### Templates owns

- repository-local Agent Core implementation and distribution;
- `.automation/**`, `.opencode/**`, `AGENTS.md`, and the root `Justfile`;
- Task lifecycle, Work Units, Task Orchestrator, and guarded Git/GitHub APIs;
- repository policy, adoption, upgrade, `VERSION`, `UPSTREAM`, and Project Adapter;
- complete Agent-Core prompts, commands, and skills.

Neither complete prompt implementations nor command/skill implementations move here. OpencodeContract does not generate, materialize, synchronize, or modify either consumer.

## Profiles

### Global Profile

`profiles/global.toml` describes the dotnix global user layer. It supports generic repositories without Agent Core. Global `build` can implement and orchestrate, global `plan` remains read-only, and repository-specific lifecycle is outside this profile. Repository-local rules may impose stronger boundaries.

### Agent-Core Profile

`profiles/agent-core.toml` describes the Templates repository-local layer. Repository-local configuration is authoritative; `build` is the Main Orchestrator rather than a direct implementation worker; one Task Orchestrator owns one Task's implementation; and raw Git/GitHub writes are constrained to guarded APIs.

The same role identity does not imply identical prompts, permissions, or authority. `build` and `general` are explicit profile variants. `task-orchestrator` is Agent-Core-only.

## Canonical contract

- `policy/models.toml`: model aliases, exact provider IDs, and quota families. Provider model literals appear only here.
- `policy/roles.toml`: canonical role taxonomy, profile applicability, and primary/subagent classification.
- `policy/model-availability.toml`: fixed-model availability, fail-closed, and exact failure-reporting requirements.
- `policy/invariants.toml`: common invariants and value-free declarations of allowed profile differences. Compared values are derived from canonical role/profile data.
- `profiles/*.toml`: profile-specific primary assignments, authority semantics, and ownership.

## Models

Only three model aliases are canonical:

- `sol` = `openai/gpt-5.6-sol`
- `terra` = `openai/gpt-5.6-terra`
- `luna` = `openai/gpt-5.6-luna`

Provider IDs appear only in `policy/models.toml`. Quota-family metadata is descriptive and is not routing authority. Spark, substitute models, and local models are not part of the canonical policy.

## Optional local-worker compatibility

[`policy/optional-workers.toml`](policy/optional-workers.toml) defines an optional, noncanonical compatibility envelope for the Global profile. The three worker classes are `local-investigator`, `local-tracer`, and `local-background`; they are implementation-owned classes rather than canonical roles or model bindings. A consumer owns provider IDs, endpoints, local model literals, prompts, runtime services, and machine-specific routing. Absence of the extension is conformant and does not change any Sol/Terra/Luna assignment or Agent-Core requirement.

Phase 1 permits explicit manual or shadow dispatch only. Workers are hidden, read-only, nonauthoritative subagents with deny-by-default permissions and only `read` and `grep` allowed. Automatic model fallback, canonical-role substitution, cross-model retry, and implicit routing are forbidden. A required-tool omission may be retried once only after an otherwise normal successful response with zero parent-observed calls to the named tool, using the same objective, agent, provider/model binding, and required tool. Availability, API, runtime, schema, permission, blocked, and wrong-evidence failures return `BLOCKED` without retry or fallback.

The parent validates paths, lines or ranges, snippets, mechanism, confidence, and unverified areas before accepting output. Worker output is untrusted, and tool-call counts come from parent-observed session events rather than worker claims. Metrics contain bounded counters and metadata only, never prompts, file content, or tool output.

OpenCode v1.18.16 does not expose its internal `toolChoice: required` control through the public plugin API. Required-tool selection, one-retry accounting, evidence validation, and single-in-flight dispatch are therefore procedural parent controls in Phase 1—not runtime guarantees. A strict audit validates declarations and static configuration only; it does not prove runtime behavior, model availability, or output correctness.

When a Global extension manifest is present beside the selected profile-owned `opencode.json` and `agents/` directory, strict audit validates the complete bundle: exact worker classes, provider/model resolution, sticky bindings, fail-closed retry declarations, metrics schema, hidden subagent metadata, and exact permissions. The selected agent directory is a closed inventory, so unregistered files—including disguised fallback agents—and partial extension deployment fail strict audit. Repository-local OpenCode layers outside that selected Global bundle remain separately authoritative and are not searched or reclassified. This envelope is tracked by [Issue #5](https://github.com/upiscium/OpencodeContract/issues/5).

## Model availability

Each applicable role has one fixed configured model. Model substitution and alternate-model retry are forbidden, including for quota, rate-limit, usage-limit, or availability failures. No hidden or manually callable model-substitution fallback agent is permitted.

When the configured provider/model cannot execute the bounded objective, the result is `BLOCKED` and the exact provider/model failure is reported. OpencodeContract guarantees policy consistency, not provider or model availability. Quality-preserving execution under this policy requires the configured GPT-5.6 role model.

## Intentionally not canonical

The contract does not canonicalize full permissions, full agent prompts, commands, skills, provider credentials, UI preferences, Task implementation mechanics, Just recipes, or Project Adapter details. Semantic authority can differ by profile even when a role name and model assignment are shared.

## Validate policy

Python 3.11 or newer is required for standard-library `tomllib`.

```sh
python tools/validate_policy.py
python -m unittest discover -s tests -v
opencode-contract validate
```

The validator parses all TOML documents and checks semantic ID uniqueness, model/role/profile references, required fields, model ID syntax, applicability consistency, complete single-model assignments, intentional differences, and the fixed model-availability contract.

## Audit consumers

The canonical CLI audits one explicitly selected profile without requiring the other consumer:

```sh
opencode-contract audit-consumer \
  --profile global \
  --consumer /path/to/dotnix \
  --strict

opencode-contract audit-consumer \
  --profile agent-core \
  --consumer /path/to/Templates \
  --strict
```

Profile selection is mandatory and is never inferred from a directory name. Audits only inspect the supplied filesystem tree, so Nix store paths and other read-only source trees are supported. A strict audit exits non-zero for invalid policy, invalid consumer paths, `DIFF`, or `MISSING` results.

The original dual-consumer workflow remains compatible:

Audit explicit local checkouts of current consumer implementations:

```sh
python tools/audit_consumers.py \
  --dotnix /path/to/dotnix \
  --templates /path/to/Templates
```

The audit is read-only and never repairs consumers. It checks primary role existence, fixed model assignments, primary/subagent modes, profile applicability, and the absence of legacy `*-fallback.md` files. The Agent-Core profile additionally forbids `.automation/model-fallback.toml`. It does not inspect Templates task-recovery commands, skills, schemas, Just APIs, or upgrade mechanics. The audit reports `PASS`, `INTENTIONAL_DIFFERENCE`, `DIFF`, and `MISSING`; unexpected mismatches are additionally labeled `UNEXPECTED_DRIFT`. Add `--strict` when unexpected drift should produce a non-zero exit status.

Consumer repositories are intentionally not cloned by CI. Policy CI therefore remains deterministic when either consumer's `main` branch changes.

## Nix flake interface

The flake supports `x86_64-linux` and `aarch64-linux` and exposes:

- `packages.<system>.default` and `packages.<system>.opencode-contract`;
- `apps.<system>.default` for the canonical `opencode-contract <subcommand>` interface;
- `checks.<system>.policy`, `checks.<system>.audit-consumer`, and `checks.<system>.tests`;
- `devShells.<system>.default` with Python 3.

Examples:

```sh
nix build .#opencode-contract
nix run .# -- validate
nix flake check
nix develop
```

The package contains only Python, policy/profile documents, and the standard-library tooling. Runtime audit execution does not require Git, GitHub CLI, network access, or a writable consumer checkout.

## Consumer dependency model

Future consumers can pin this repository as a normal flake input:

```nix
inputs.opencodeContract.url = "github:upiscium/OpencodeContract";
inputs.opencodeContract.inputs.nixpkgs.follows = "nixpkgs";
```

The consumer's `flake.lock` owns the exact OpencodeContract Git revision. The consumer check invocation separately owns the explicit profile selection: Templates uses `--profile agent-core`, while dotnix uses `--profile global`. Profiles are not stored in `flake.lock`.

The locked Git revision is dependency identity. It is separate from `schema_version = 1`, which continues to identify the machine-readable policy document schema.

Consumer updates are deliberate dependency updates, for example:

```sh
nix flake update opencodeContract
```

Consumers do not follow OpencodeContract `main` at audit runtime. OpencodeContract has no input or runtime dependency on Templates or dotnix, preserving the one-way dependency direction.

## Current consumers

| Consumer | Profile | Implementation owner |
| --- | --- | --- |
| `upiscium/dotnix` | `global` | dotnix |
| `upiscium/Templates` | `agent-core` | Templates |

## Consumer transitions

Consumers advance this contract only by explicitly updating their pinned OpencodeContract revision. A consumer may therefore remain conformant to an older locked policy while its implementation migration is pending; movement of OpencodeContract `main` alone does not change that consumer's audit dependency.

Profile migrations must preserve implementation ownership, avoid runtime network dependencies, and prevent dependency cycles. OpencodeContract does not generate or materialize consumer configuration.
