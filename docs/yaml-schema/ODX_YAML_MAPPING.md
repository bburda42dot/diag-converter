# ODX → YAML mapping (OpenSOVD CDA diagdesc v1)

This document maps common **ODX concepts** (as seen in typical ODX content, `odxtools`, and what `odx-converter` persists) to the **OpenSOVD CDA Diagnostic Description** YAML/JSON schema in this folder.

- YAML/JSON normative schema: [schema.json](schema.json)
- Example document: [example-ecm.yml](../../test-fixtures/yaml/example-ecm.yml)
- Semantic validator: `diag-yaml` crate (`semantic_validator` module)

## Notes

- “YAML paths” below are *conceptual*: many sections are maps, so keys vary (e.g., session name, DID number).
- This format is intentionally **client-oriented** (describe what a UDS client needs), not a full ODX database model.
- We aim to be **ODX-mappable without embedding ODX references**: ODX → YAML import should preserve behavior in most practical cases, but the YAML does not carry ODX IDs/links.

## Goals and non-goals

**Goals**

- Human-friendly authoring (YAML), strict validation (JSON Schema + semantic checks).
- Replace ODX in most day-to-day diagnostic client use-cases without requiring automotive-grade authoring tools.
- Maintain a clear ODX → YAML mapping for importers.

**Non-goals (accepted lossiness)**

- No round-trip YAML → ODX preserving original identities (no ODXLINK/SNREF anchoring).
- No complete modeling of all ODX request/response parameter semantics and DOP conversion machinery.
- No full DiagLayer inheritance graph parity.

## Mapping table

| ODX concept (ODX / odxtools / odx-converter) | What it represents                                      | YAML/JSON mapping (paths)                                                                                                        | Human-friendly substitute in this format     | Notes / accepted lossiness                                                                    |
| -------------------------------------------- | ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Document identity / versioning               | Which schema/version a document follows                 | `schema`, `meta.*`                                                                                                               | Fixed schema string + simple metadata        | No ODX document packaging/modeling; only what authors/tools need.                             |
| ECU identity                                 | ECU name / logical identity                             | `ecu.id`, `ecu.name`                                                                                                             | Stable ECU identifiers                       | Does not preserve ODX naming/identity graph.                                                  |
| Addressing (DoIP/CAN)                        | How to reach ECU (addresses, IP, ports)                 | `ecu.addressing.doip.*`, `ecu.addressing.can.*`                                                                                  | Direct transport addressing                  | ECU-level addressing only; per-service addressing nuances may be lost.                        |
| Timing parameters (UDS/transport)            | P2/P2*/S3 style timings                                 | `ecu.addressing.timing.*`, `sessions.*.timing.*`                                                                                 | Simple timing overrides                      | Not a full protocol timing/comparam model.                                                    |
| ComParams / ProtStack / transport params     | Protocol-scoped communication parameters and defaults   | `comparams.doip.*`, `comparams.can.*`, `comparams.uds.*`, `comparams.iso15765.*`                                                 | Simple key/value comparams                   | No full ProtStack graph; keys are conventions, not ODX objects.                               |
| Diagnostic sessions                          | Supported sessions and IDs                              | `sessions.<name>.id`, `sessions.<name>.*`                                                                                        | Named sessions                               | No ODX session objects/links; just what the client needs.                                     |
| SecurityAccess (UDS 0x27)                    | Seed/key levels and constraints                         | `security.<level_name>.*`                                                                                                        | Named security levels                        | Client-oriented subset; enforcement via `access_patterns` + `state_model`.                    |
| Authentication (UDS 0x29)                    | Roles, anti-brute-force, auth flow                      | `authentication.anti_brute_force.*`, `authentication.roles.<role>.*`                                                             | Named roles + throttling                     | Client-oriented subset; not a full ODX auth graph.                                            |
| State charts / transitions                   | Formal state machines and service-triggered transitions | `state_model.*`, `services.<svc>.state_effects.*`                                                                                | Pragmatic state tracker                      | Not a general statechart model; focuses on session/security/auth role.                        |
| Services (DiagService/DiagComm)              | Which UDS services are supported                        | `services.<serviceName>.enabled` and service-specific fields                                                                     | Enabled/disabled services                    | No complete parameterization for all services; schema enumerates supported service blocks.    |
| Request/response parameter model             | Full request/response parameterization, DOPs, NRCs      | Partially: `services.readDataByIdentifier.response_outputs` and `response_param_match.request_params`                            | Minimal response shape + match rules         | Intentionally not a full generic ODX runtime description for all request/response parameters. |
| Response output parameters (OUT-PARAM-IF)    | Named output fields/structures for matching             | `services.readDataByIdentifier.response_outputs.<name>...`                                                                       | `response_outputs` tree                      | Modeled where needed for `response_param_match`; not guaranteed for every service.            |
| MatchingParameter (variant detection)        | Match a concrete response field value                   | `identification.expected_idents.*.conditions[].response_param_match` and/or `variants.definitions.*.detect.response_param_match` | `response_param_match` + dotted `param_path` | Paths reference our response shape contract, not ODX param graphs.                            |
| VariantPattern / ExpectedIdent               | Reusable identification checks and patterns             | `identification.expected_idents.<name>.*`                                                                                        | Reusable condition lists                     | We preserve behavior (match conditions), not ODX typed `IdentValue` identities.               |
| Variant selection and overrides              | Pick a variant and override base capabilities           | `variants.detection_order`, `variants.fallback`, `variants.definitions.<variant>.*`                                              | Overrides instead of DiagLayer graphs        | No full ODX inheritance graph; importer flattens to overrides.                                |
| Probe context                                | Which state to enter before probing                     | `identification.expected_idents.*.probe_context`, `variants.definitions.*.detect.probe_context`                                  | Simple probe context                         | Not a full ODX execution-context model; enough for clients.                                   |
| Access control policies                      | Who can do what in which state                          | `access_patterns.<name>.*`, referenced by DIDs/routines                                                                          | Reusable access patterns                     | Requires client state tracking to enforce; not an ODX access concept.                         |
| DIDs (Data Identifiers)                      | Data items read/written by 0x22/0x2E/0x2F               | `dids.<did>.name`, `dids.<did>.type`, `dids.<did>.access`, plus flags                                                            | Simple DID catalog                           | Key typing differences in YAML prevent strict key-pattern validation.                         |
| Routines (RoutineControl)                    | Named routines and allowed operations                   | `routines.<rid>.*`                                                                                                               | Simple routine catalog                       | No ODX job model (SingleEcuJob) unless added explicitly.                                      |
| DTCs and DTC config                          | DTC definitions, snapshot/extended-data config          | `dtc_config.*`, `dtcs.<dtc>.*`                                                                                                   | Minimal DTC metadata                         | Not full ODX DTC metadata / text localization model.                                          |
| Audience gating                              | Visibility constraints by tool context                  | `audience.*` (top-level), plus `dids.*.audience`, `routines.*.audience`, and `services.readDataByIdentifier.audience`            | Boolean flags + groups                       | Per-service audience is not consistently exposed for all service blocks.                      |
| SDGs / SD / SI / TI                          | Hierarchical special-data groups + language tags        | `sdgs.<name>.si/caption/values[]` (recursive), leaf entries with `si/ti/value`                                                   | Optional SDG tree                            | Metadata-only; does not affect diagnostics semantics by itself.                               |
| Annotations (lightweight SDG-style)          | Flat key/value metadata and quirks                      | `annotations.*` and per-element `annotations` where available                                                                    | Simple key/value metadata                    | Flat only; no TI/language unless using `sdgs`.                                                |
| OEM extensions                               | Vendor-specific payload                                 | `x-oem`                                                                                                                          | Escape hatch for OEM data                    | Intentionally unstructured; importer/consumer-specific.                                       |

## What validation enforces (beyond JSON Schema)

The `diag-yaml` semantic validator adds checks that JSON Schema doesn’t naturally express, including:

- Session/security/auth role references in `state_model`, `access_patterns`, `probe_context`.
- `variants.detection_order`/`fallback` referencing existing variant names.
- `variants.definitions.*.detect.ident_ref` referencing `identification.expected_idents`.
- `response_param_match.service` referencing an existing key in `services`.
