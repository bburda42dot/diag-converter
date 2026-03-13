# FBS Schema Limitations (MDD Format)

The MDD binary format uses a FlatBuffers schema
(`mdd-format/schemas/diagnostic_description.fbs`) that must stay identical to
the upstream odx-converter (Kotlin). Not all IR (`DiagDatabase`) fields can be
represented in the FBS `EcuData` root table.

## Fields lost during MDD serialization

| IR field | In FBS? | Notes |
|---|---|---|
| `protocols` | No | Protocol layers are not in `EcuData`. Per-service protocol associations (`DiagComm.protocols`) ARE serialized inside each service's FBS `DiagComm`. |
| `ecu_shared_datas` | No | ECU shared data layers are not in `EcuData`. They only appear as `ParentRef` variants. |
| `memory` | No | `MemoryConfig` is not in the shared schema. Only populated by the YAML parser. |
| `type_definitions` | No | `TypeDefinition` is not in the shared schema. Only populated by the YAML parser. |

## Conversion fidelity by path

| Path | Fidelity | What is lost |
|---|---|---|
| ODX -> ODX | Lossless | - |
| ODX -> MDD | Lossy | `protocols`, `ecu_shared_datas` as top-level collections |
| YAML -> MDD | Lossy | `memory`, `type_definitions` |
| MDD -> IR | Lossy | Fields not in `EcuData` come back empty |

## Why not extend EcuData?

The FBS schema is shared with the odx-converter (Kotlin reference
implementation). Adding fields unilaterally would create schema divergence.
Any extension must be coordinated upstream.
