# SCHEMA.md — OpenSOVD CDA Diagnostic Description Reference

This document is the complete reference for writing YAML/JSON documents that validate against [schema.json](schema.json).

## Quick Links

| Resource                                                           | Description              |
| ------------------------------------------------------------------ | ------------------------ |
| [schema.json](schema.json)                                         | Normative JSON Schema    |
| [minimal-ecu.yml](../../test-fixtures/yaml/minimal-ecu.yml)        | Minimal example          |
| [example-ecm.yml](../../test-fixtures/yaml/example-ecm.yml)        | Full example             |
| [ODX_YAML_MAPPING.md](ODX_YAML_MAPPING.md)                         | ODX → YAML mapping       |

---

## Document Encoding Notes

### Hex scalars

Many fields accept either:

- an **integer** (e.g. `61456`), or
- a **hex string** in the form `0x...` (e.g. `"0xF010"`).

For YAML authors, unquoted `0xF190` may be parsed as an integer by some YAML parsers; this is why the schema often allows both representations.

### Hex keys in YAML maps

Sections like `dids`, `dtcs`, and `routines` are modeled as maps where the *keys* are the numeric identifiers (e.g. DID 0xF190). JSON Schema cannot reliably validate YAML map keys that may be parsed as integers vs strings, so the schema intentionally does **not** enforce key patterns for those maps.

---

## References and Cross-Links

The schema uses **string references** across sections (e.g. an access pattern name referenced by a DID). These are semantically meaningful, but most of them are not validated at the JSON Schema level (JSON Schema does not naturally express "map key exists elsewhere" constraints).

Common references:

- **Session name**: keys under `sessions` (e.g. `default`, `extended`)
- **Security level name**: keys under `security` (e.g. `level_01`)
- **Authentication role name**: keys under `authentication.roles` (e.g. `factory`)
- **Access pattern name**: keys under `access_patterns` (e.g. `public`, `secured_write`)
- **Type name**: keys under `types`
- **Snapshot / extended-data names**: keys under `dtc_config.snapshots` / `dtc_config.extended_data`
- **Variant name**: keys under `variants.definitions` (e.g. `bootloader`, `application_v1`)
- **Expected ident name**: keys under `identification.expected_idents` (e.g. `bootloader_ident`)

The `diag-yaml` semantic validator performs semantic validation of these cross-references.

---

## Schema Sections

### 1. `meta`

Document metadata.

**Required fields:**
- `author` (string)
- `domain` (string)
- `created` (date: `YYYY-MM-DD`)
- `revision` (semver: `X.Y.Z`)
- `description` (string)

**Optional fields:**
- `tags` (string array)
- `revisions[]` (changelog entries with `version`, `date`, `author`, `changes`)

---

### 2. `ecu`

ECU identity, protocol configuration, and addressing.

**Required:** `id`, `name`, `addressing`

**Optional:** `protocols`, `default_addressing_mode`, `annotations`

**`ecu.protocols`:**

If multiple protocols are defined, exactly **one** must have `is_default: true`. The default protocol's comparams and addressing are used when not explicitly specified.

```yaml
ecu:
  protocols:
    doip:
      protocol_short_name: "UDSonDoIP"
      description: "UDS over DoIP"
      is_default: true
    can:
      protocol_short_name: "UDSonCAN"
      description: "UDS over CAN"
```

**Canonical Protocol Names:**
- `UDSonDoIP` - UDS over DoIP (ISO 13400)
- `UDSonCAN` - UDS over CAN (ISO 15765)
- `UDSonLIN` - UDS over LIN
- `UDSonFR` - UDS over FlexRay
- `ISO_14229_3_DoIP` - ISO 14229-3 DoIP variant
- `ISO_15765_3_CAN` - ISO 15765-3 CAN variant

**`ecu.default_addressing_mode`:**

Global default for service addressing. Can be overridden per service.

```yaml
ecu:
  default_addressing_mode: physical  # Options: physical, functional, both
```

**`ecu.addressing` supports:**

- **`doip`:**
  - Required: `ip`, `logical_address`, `tester_address`
  - Optional: `port`, `functional_address`, `routing_activation`
- **`can`:**
  - Optional: `physical_request`, `physical_response`, `functional_request` (all hex32)
- **`timing`:**
  - Optional: `p2_ms`, `p2_star_ms`, `s3_ms`

---

### 3. `sessions`

Defines available diagnostic sessions per ISO 14229-1.

| Session         | ID     | Description                            |
| --------------- | ------ | -------------------------------------- |
| `default`       | 0x01   | Default session, limited functionality |
| `programming`   | 0x02   | ECU reprogramming mode                 |
| `extended`      | 0x03   | Extended diagnostic session            |
| OEM (0x40-0x7E) | varies | Manufacturer/supplier specific         |

```yaml
sessions:
  default:
    id: 0x01
  extended:
    id: 0x03
  programming:
    id: 0x02
    requires_unlock: true
```

**Each session entry:**
- Required: `id` (hex8)
- Optional: `alias`, `requires_unlock`, `timing.p2_ms`, `timing.p2_star_ms`

---

### 4. `state_model`

Defines the ECU's state machine, enabling clients to:

1. Know the initial state after power-on or reset
2. Understand which state transitions are valid
3. Predict how service calls affect state (via `state_effects` on services)

```yaml
state_model:
  initial_state:
    session: default
    security: none
    authentication_role: none

  session_transitions:
    default: [extended, programming]
    extended: [default, programming]
    programming: [default, extended]

  session_change_resets_security: true
  session_change_resets_authentication: true
  s3_timeout_resets_to_default: true
```

**Fields:**

- `initial_state`: ECU state after power-on or hard reset
  - `session`: session name (required)
  - `security`: `none` or security level name (default: `none`)
  - `authentication_role`: `"none"` or role name (default: `"none"`)
- `session_transitions`: map of `from_session -> [allowed_target_sessions]`
- `session_change_resets_security`: if `true`, changing session resets `security` to `none`
- `session_change_resets_authentication`: if `true`, changing session clears `authentication_role`
- `s3_timeout_resets_to_default`: if `true`, S3 timeout (no testerPresent) returns ECU to `initial_state`

**State Effects on Services:**

Services that modify ECU state can declare their effects:

```yaml
services:
  diagnosticSessionControl:
    enabled: true
    state_effects:
      on_success:
        session: from_request
        security: none
        authentication_role: none

  ecuReset:
    enabled: true
    state_effects:
      hardReset:
        session: default
        security: none
        authentication_role: none
      softReset:
        session: unchanged
        security: none
        authentication_role: none

  securityAccess:
    enabled: true
    state_effects:
      on_unlock:
        security: from_request

  authentication:
    enabled: true
    state_effects:
      on_authenticate:
        authentication_role: from_request
      on_deauthenticate:
        authentication_role: none
```

**State Effect Values:**

- `"unchanged"`: state component is not modified
- `"from_request"`: state is set based on the service request/response
- Explicit value (session name, integer, `"none"`): state is set to this value

---

### 5. `security`

Security access levels per UDS 0x27.

```yaml
security:
  level_01:
    level: 1
    seed_request: 0x01
    key_send: 0x02
    seed_size: 16
    key_size: 16
    algorithm: "aes_cmac_v1"
    max_attempts: 3
    delay_on_fail_ms: 10000
    allowed_sessions: [extended, programming]
```

`security` is a map `level_name -> security_level`.

**Each security level requires:**
- `level` (uint8)
- `seed_request` / `key_send` (hex8)
- `seed_size` / `key_size` (uint8)
- `algorithm` (string)
- `max_attempts` (uint8)
- `delay_on_fail_ms` (uint32)
- `allowed_sessions` (string list)

---

### 6. `authentication`

Optional UDS 0x29-related configuration.

- **`anti_brute_force`**: `max_attempts`, `delay_initial_s`, `delay_max_s`, `delay_multiplier`
- **`roles`**: map `role_name -> role` where each role requires:
  - `id` (hex8)
  - `timeout_s` (uint16)
  - `certificate_ref` (string)
  - `allowed_sessions` (string list)
  - `proof_of_ownership` (boolean)

---

### 7. `variants`

Variant detection enables a single diagnostic description to support multiple ECU configurations:

- **Bootloader vs Application**: Different services available in each mode
- **Software versions**: V1 vs V2 may have different capabilities
- **Unknown/fallback**: Safe mode for unidentified variants

```yaml
variants:
  detection_order: [bootloader, application_v2, application_v1]
  fallback: unknown

  definitions:
    bootloader:
      description: "ECU in bootloader/flashing mode"
      detect:
        ident_ref: bootloader_ident
      overrides:
        services:
          readDTCInformation:
            enabled: false
          requestDownload:
            enabled: true
      annotations:
        mode: "bootloader"

    application_v2:
      description: "Application software version 2.x"
      detect:
        match_all:
          - did_match:
              did: 0xF195
              value_starts_with: "2."
          - did_match:
              did: 0xF1F0
              value_equals: 0x00
      annotations:
        sw_generation: 2

    unknown:
      description: "Safe mode - minimal access"
      detect:
        match_any:
          - session_available: [default]
          - service_responds:
              service: diagnosticSessionControl
              subfunction: 0x01
      overrides:
        services:
          writeDataByIdentifier:
            enabled: false
          routineControl:
            enabled: false
      annotations:
        mode: "safe"
```

**Detection Methods:**

**Simple (single condition - legacy shorthand):**
- `did_match`: Read a DID and match its value
  - `value_equals`: Exact match (string or hex)
  - `value_starts_with`: String prefix match
  - `value_contains`: Substring match
  - `value_regex`: Regex pattern match
  - `bitmask`: `{ mask: 0xFF, expected: 0x01 }` for bitwise matching
- `session_available`: Variant matches if listed sessions can be entered
- `service_responds`: Probe a service; variant matches if positive response

**Multi-condition (ODX-inspired):**
- `ident_ref`: Reference a named identification check from `identification.expected_idents`
- `match_all`: Array of conditions; ALL must match (AND logic)
- `match_any`: Array of conditions; at least ONE must match (OR logic)

**Probe Context:**

Optional `probe_context` specifies the state in which to perform detection:

```yaml
detect:
  match_all:
    - did_match:
        did: 0xF195
        value_starts_with: "2."
  probe_context:
    session: extended
    security: level_01
    authentication: tester
```

**Overrides:**

Each variant can override: `services`, `dids`, `routines`, `access_patterns`, `state_model`

---

### 8. `identification`

Reusable expected identification checks, inspired by ODX `ExpectedIdent`.

```yaml
identification:
  expected_idents:
    bootloader_ident:
      description: "ECU is in bootloader mode"
      conditions:
        - did_match:
            did: 0xF1F0
            value_equals: 0x01
        - did_match:
            did: 0xF1F1
            bitmask:
              mask: 0x80
              expected: 0x00
      probe_context:
        session: default

    application_v2_ident:
      description: "Application software version 2.x"
      conditions:
        - did_match:
            did: 0xF195
            value_starts_with: "2."
        - did_match:
            did: 0xF1F0
            value_equals: 0x00
```

**Structure:**
- `expected_idents`: Map of `ident_name -> expected_ident`
- Each `expected_ident` contains:
  - `description`: Human-readable description
  - `conditions`: Array of conditions (implicit AND - all must match)
  - `probe_context` (optional): State context for probing

**Usage in Variants:**

```yaml
variants:
  definitions:
    bootloader:
      detect:
        ident_ref: bootloader_ident
```

---

### 9. `services`

`services` is a strict object with known UDS services as properties. Each service entry requires at least `enabled: true|false`.

**Common Optional Fields (available on most services):**
- `addressing_mode`: `physical`, `functional`, or `both` (overrides `ecu.default_addressing_mode`)
- `request_layout`: Custom request parameter layout (see below)

**Supported services and their optional fields:**

| Service                           | Optional Fields                                                                           |
| --------------------------------- | ----------------------------------------------------------------------------------------- |
| `diagnosticSessionControl`        | `addressing_mode`, `request_layout`, `subfunctions`, `state_effects`                      |
| `ecuReset`                        | `addressing_mode`, `request_layout`, `subfunctions`, `state_effects`                      |
| `securityAccess`                  | `addressing_mode`, `request_layout`, `state_effects`                                      |
| `authentication`                  | `addressing_mode`, `request_layout`, `subfunctions`, `state_effects`                      |
| `testerPresent`                   | `addressing_mode`                                                                         |
| `controlDTCSetting`               | `addressing_mode`                                                                         |
| `clearDiagnosticInformation`      | `addressing_mode`                                                                         |
| `readDataByIdentifier`            | `addressing_mode`, `request_layout`, `audience`, `response_outputs`                       |
| `writeDataByIdentifier`           | `addressing_mode`, `request_layout`                                                       |
| `inputOutputControlByIdentifier`  | `addressing_mode`, `control_types`                                                        |
| `routineControl`                  | `addressing_mode`, `request_layout`, `subfunctions`, `audience`, `response_outputs`       |
| `readDTCInformation`              | `addressing_mode`, `request_layout`, `subfunctions`, `audience`, `response_outputs`       |
| `communicationControl`            | `addressing_mode`, `request_layout`, `subfunctions`, `communication_types`, `nrc_on_fail` |
| `responseOnEvent`                 | `subfunctions`, `max_active_events`                                                       |
| `linkControl`                     | `subfunctions`                                                                            |
| `readMemoryByAddress`             | `alfid`, `max_length`, `regions[]`                                                        |
| `writeMemoryByAddress`            | `alfid`, `max_length`, `regions[]`                                                        |
| `readScalingDataByIdentifier`     | `dids[]`                                                                                  |
| `readDataByPeriodicIdentifier`    | `subfunctions`, `supported_periods_ms[]`, `identifiers[]`                                 |
| `dynamicallyDefineDataIdentifier` | `subfunctions`, `max_dynamic_dids`, `allow_by_identifier`, `allow_by_memory_address`      |
| `requestDownload`                 | `max_number_of_block_length`, `regions[]`                                                 |
| `requestUpload`                   | `max_number_of_block_length`, `regions[]`                                                 |
| `transferData`                    | `max_block_sequence_counter`                                                              |
| `requestTransferExit`             | —                                                                                         |
| `requestFileTransfer`             | `subfunctions`, `max_file_size`                                                           |
| `securedDataTransmission`         | `subfunctions`                                                                            |
| `custom`                          | Map of custom OEM services (see below)                                                    |

**Custom Services:**

For OEM/proprietary services not covered by standard UDS:

```yaml
services:
  custom:
    myOemService:
      sid: 0xBA
      description: "OEM-specific service"
      addressing_mode: physical
      request_layout:
        use_uds_defaults: false
        parameters:
          - name: "commandId"
            byte_position: 1
            bit_length: 8
            semantic: subfunction
      access: factory_access
```

**Request Layout:**

Override UDS-default parameter positions when needed. All byte positions are 1-indexed (position 1 = first byte after SID).

```yaml
services:
  routineControl:
    enabled: true
    request_layout:
      use_uds_defaults: true  # Default, uses standard positions
      # Override specific positions if needed:
      # subfunction_position: 1
      # rid_position: 2
      # rid_byte_length: 2
```

For non-standard layouts, define explicit parameters:

```yaml
request_layout:
  use_uds_defaults: false
  parameters:
    - name: "subfunction"
      byte_position: 1
      bit_length: 7
      semantic: subfunction
    - name: "customParam"
      byte_position: 2
      bit_length: 16
      semantic: data
```

---

### 10. `access_patterns`

Reusable access control definitions combining sessions, security, and authentication.

```yaml
access_patterns:
  public:
    sessions: any
    security: none
    authentication: none

  secured_write:
    sessions: [extended]
    security: [level_01]
    authentication: none

  factory_access:
    sessions: [extended, programming]
    security: [level_01]
    authentication: [factory, oem]
    nrc_on_fail: 0x33
```

**Required fields:**
- `sessions`: either `"any"` or a list of session names
- `security`: either `"none"` or a list of security level names
- `authentication`: either `"none"` or a list of authentication role names

**Optional fields:**
- `nrc_on_fail`: hex8 (NRC if access is denied)

---

### 11. `types`

Data type definitions with physical conversion.

**Core deterministic types:**

For reliable, deterministic conversion to a downstream runtime database format, use these types:

| Base Type                  | Requirements                              | Notes                    |
| -------------------------- | ----------------------------------------- | ------------------------ |
| `u8`, `s8`                 | None                                      | 8-bit integers           |
| `u16`, `u32`, `s16`, `s32` | `endian` required                         | Multi-byte integers      |
| `ascii`                    | `length` required, `encoding` recommended | Fixed-length strings     |
| `bytes`                    | `length` required                         | Fixed-length byte arrays |

```yaml
types:
  temperature:
    base: u8
    scale: 1
    offset: -40
    unit: "degC"
    constraints:
      physical: [-40, 215]

  engine_speed:
    base: u16
    endian: big  # Required for multi-byte types
    scale: 0.25
    unit: "rpm"

  vin_type:
    base: ascii
    length: 17  # Fixed length required
    encoding: "US-ASCII"
    pattern: "^[A-HJ-NPR-Z0-9]{17}$"

  raw_data:
    base: bytes
    length: 32  # Fixed length required
```

**Extended Types (May Require Heuristics):**

These types are supported but may need special handling during conversion:

| Base Type    | Notes          |
| ------------ | -------------- |
| `u64`, `s64` | Large integers |
| `f32`, `f64` | Floating point |

**Variable-Length Types (Advanced):**

Variable-length types (`min_length`/`max_length` with `termination`) are supported but should be avoided when possible for deterministic conversion:

```yaml
types:
  # ADVANCED: Variable-length - use only when fixed length is not possible
  variable_string:
    base: ascii
    min_length: 1
    max_length: 255
    termination: "zero"  # Null-terminated
    encoding: "US-ASCII"
```

**Termination Methods:**
- `zero`: Null-terminated string
- `end_of_pdu`: Consumes remaining PDU bytes
- `length_field`: Requires separate length field (not fully supported)
- `none`: No termination (use with fixed `length`)

**Type variants:**

- **Atomic type** (`base: u8|u16|u32|u64|s8|s16|s32|s64|f32|f64|ascii|bytes`):
  - `endian: big|little` (REQUIRED for types > 8 bits)
  - `bit_length`: Explicit bit length
  - `bit_position`: Sub-byte field position (0 = LSB, 7 = MSB)
  - `length` (for `ascii`/`bytes`): Fixed length (REQUIRED for deterministic conversion)
  - `min_length` / `max_length`: Variable length bounds (advanced)
  - `encoding`: Character encoding (`US-ASCII`, `UTF-8`, `ISO-8859-1`, `UCS-2`)
  - `termination`: Field termination (`zero`, `length_field`, `end_of_pdu`, `none`)
  - `scale` / `offset`: Linear conversion (physical = internal * scale + offset)
  - `unit`, `pattern`
  - `constraints.internal` / `constraints.physical`: `[min, max]`
  - `validation.forbidden_characters`, `validation.forbidden_values`
- **Enum type** (`base: u8|u16`, `enum: <map>`)
- **Struct type** (`base: struct`, `size`, `fields[]`)
- **Text table** (`base: <numeric>`, `entries[]`) - see below

**Text Table (full enum with ranges):**

For complex coded-to-text conversion with ranges (ODX TEXT-TABLE equivalent):

```yaml
types:
  gear_position:
    base: u8
    entries:
      - value: 0x00
        text: "Park"
      - value: 0x01
        text: "Reverse"
      - range: [0x02, 0x08]
        text: "Drive"
        description: "Forward gears 1-7"
      - value: 0x0F
        text: "Neutral"
    default_text: "Unknown"
```

**Linear Conversion (advanced):**

For full rational scaling with constraints:

```yaml
types:
  battery_voltage:
    base: u16
    endian: big
    conversion:
      scale: 1
      offset: 0
      divisor: 1000
      unit: "V"
      internal_constraints: [0, 65535]
      physical_constraints: [0, 65.535]
```

Formula: `physical = (internal - offset) * scale / divisor`

**Bitmask:**

For packed bit fields:

```yaml
types:
  status_flags:
    base: u8
    bitmask: 0x0F  # Only lower 4 bits used
```

---

### 11a. Response Structures (Advanced)

For services requiring full response layout control, use `positive_response` and `negative_responses`:

```yaml
services:
  custom:
    readVehicleStatus:
      sid: 0xB1
      description: "Read vehicle status"
      positive_response:
        sid: 0xF1
        parameters:
          - name: statusByte
            param_id: status
            semantic: status
            byte_position: 1
            bit_length: 8
            type:
              base: u8
          - name: faultCount
            param_id: faults
            semantic: count
            byte_position: 2
            bit_length: 8
            count_of: faultList
          - name: faultList
            param_id: faults_array
            semantic: data
            byte_position: 3
            type:
              base: u16
              endian: big
        structure:
          endian: big
          elements:
            - name: header
              byte_position: 0
              bit_length: 8
              semantic: sid
            - group_name: faultGroup
              repeat:
                count_param: faults
              elements:
                - name: faultCode
                  type:
                    base: u16
                    endian: big
      negative_responses:
        - nrc: 0x12
          name: "subFunctionNotSupported"
        - nrc: 0x22
          name: "conditionsNotCorrect"
```

**Repeat Specification:**

```yaml
repeat:
  count_param: "numItems"     # Count from another parameter
  # OR
  fixed_count: 5              # Fixed number of repetitions
  # OR
  until_end: true             # Repeat until end of PDU
  # Optional bounds:
  min_count: 0
  max_count: 255
```

**Conditional Parameters:**

```yaml
parameters:
  - name: optionalData
    condition:
      if_equals:
        param: statusByte
        value: 0x01
    type:
      base: u8
```

**Union/Choice:**

```yaml
structure:
  elements:
    - choice_name: dataVariant
      discriminator: messageType
      options:
        - when: 0x01
          then:
            - name: tempData
              type: { base: u16, endian: big }
        - when: 0x02
          then:
            - name: pressureData
              type: { base: u32, endian: big }
      default_option:
        - name: rawData
          type: { base: bytes, length: 4 }
```

---

### 11b. Communication Parameters

Communication parameters use a flat per-parameter format. Each key is a parameter name, each value is either a scalar (short form) or an object with metadata and per-protocol values:

```yaml
comparams:
  # Full form - with metadata and per-protocol values
  P2_Client:
    cptype: uint16
    unit: ms
    description: "Client-side P2 timeout"
    default: 50
    min: 10
    max: 5000
    values:
      global: 50
      uds: 50

  # Minimal form - only per-protocol values
  CP_DoIPLogicalGatewayAddress:
    values:
      UDS_Ethernet_DoIP: "4096"
      UDS_Ethernet_DoIP_DOBT: "4096"

  # Complex values (ordered list)
  CP_UniqueRespIdTable:
    cptype: complex
    values:
      UDS_Ethernet_DoIP: ["4096", "0", "FLXC1000"]

  # Short form - scalar value, no metadata needed
  CAN_FD_ENABLED: false
  MAX_DLC: 8
```

**Parameter fields** (all optional except for the short form scalar):

| Field | Type | Description |
|-------|------|-------------|
| `cptype` | string | Data type: `uint8`, `uint16`, `uint32`, `int8`, `int16`, `int32`, `float`, `string`, `boolean`, `bytes`, `complex` |
| `unit` | string | Unit of measurement (e.g., `ms`, `bytes`, `bps`) |
| `description` | string | Human-readable description |
| `default` | scalar | Default value |
| `min` | number | Minimum allowed value |
| `max` | number | Maximum allowed value |
| `allowed_values` | array | Enumeration of allowed values |
| `values` | map | Protocol-scoped values (keys: `global`, `doip`, `can`, `uds`, `iso15765`, or specific protocol identifiers) |

---

### 11c. Variant Inheritance

Control how variants inherit and merge with base configuration:

```yaml
variants:
  definitions:
    base_application:
      description: "Base application configuration"
      # Full definition here...

    application_v2:
      description: "Version 2 - extends base"
      inheritance:
        mode: merge           # merge | override | none
        extends: base_application
        merge_arrays: append  # replace | append | prepend
        allow_delete: false   # If true, null values delete base items
      detect:
        did_match:
          did: 0xF195
          value_starts_with: "2."
      overrides:
        services:
          # These are merged with base_application services
          newServiceV2:
            enabled: true
        dids:
          # Merged with base_application DIDs
          0x3000:
            name: "NewDIDv2"
            type: { base: u8 }
            access: public
```

**Inheritance Modes:**

| Mode       | Behavior                                                    |
| ---------- | ----------------------------------------------------------- |
| `merge`    | Deep merge variant on top of base, variant takes precedence |
| `override` | Variant completely replaces base (no merge)                 |
| `none`     | No inheritance, variant must be complete (full duplication) |

**Array Merge:**

| Mode      | Behavior                              |
| --------- | ------------------------------------- |
| `replace` | Variant array replaces base array     |
| `append`  | Variant items added after base items  |
| `prepend` | Variant items added before base items |

---

### 12. `dids`

Data Identifiers for read/write operations (0x22/0x2E/0x2F).

```yaml
dids:
  0xF190:
    name: "VIN"
    type:
      base: ascii
      length: 17
    access: public
    readable: true
    writable: false
    snapshot: false

  0x2001:
    name: "FuelPump"
    type:
      base: u8
    access: secured_write
    io_control:
      enabled: true
      return_control_to_ecu: true
      short_term_adjustment: true
```

**Required:** `name`, `type`, `access`

**Optional:** `description`, `readable`, `writable`, `snapshot`, `io_control`, `audience`, `annotations`

---

### 13. `routines`

Routine Control definitions (UDS 0x31).

```yaml
routines:
  0xFF01:
    name: "CylinderBalanceTest"
    access: secured_write
    operations: [start, stop, result]
    parameters:
      start:
        input:
          - name: cylinderMask
            type:
              base: u8
      result:
        output:
          - name: status
            type:
              base: u8
              enum:
                0: pass
                1: fail
```

**Required:** `name`, `access`, `operations` (list of `start`, `stop`, `result`)

**Optional:** `description`, `parameters`, `audience`, `annotations`

---

### 14. `dtc_config` and `dtcs`

**`dtc_config`** defines reusable snapshot and extended-data record metadata:

```yaml
dtc_config:
  status_availability_mask: 0x7F
  snapshots:
    current:
      record_number: 0x01
      trigger: testFailed
      update: true
      dids: [0x1001, 0x1002]
  extended_data:
    occurrenceCounter:
      record_number: 0x01
      type:
        base: u8
```

**`dtcs`** is a map of DTC definitions:

```yaml
dtcs:
  0x012300:
    name: "ThrottlePositionHigh"
    sae: "P0123"
    description: "Throttle Position Sensor A Circuit High"
    severity: 2
    snapshots: [current]
    extended_data: [occurrenceCounter]
```

**DTC required:** `name`, `sae`

**DTC optional:** `description`, `severity` (1-4), `snapshots`, `extended_data`, `x-oem`

---

### 15. `annotations`

Key-value metadata for client-specific behavior, quirks, and feature flags.

```yaml
annotations:
  supports_doip: true
  supports_can: true
  recommended_tester_present_ms: 2000
  oem_spec_document: "ECM-DIAG-SPEC-2026-001"
  quirks:
    - "P2* may exceed 5000ms during throttle adaptation"
    - "Security access delay resets on session change"
```

**Allowed at:** root, `ecu`, `variants.definitions.*`, `dids.*`, `routines.*`

**Value types:** `string`, `number`, `boolean`, `string[]`

---

### 16. `x-oem`

OEM-specific extensions. Intentionally unstructured.

```yaml
x-oem:
  note: "Placeholder for OEM extensions"
  internal_project_code: "ECM-2026-ALPHA"
```

---

## Supported UDS Services

| SID                                                      | Service                        | Support     |
| -------------------------------------------------------- | ------------------------------ | ----------- |
| 0x10                                                     | DiagnosticSessionControl       | Full        |
| 0x11                                                     | ECUReset                       | Full        |
| 0x14                                                     | ClearDiagnosticInformation     | Full        |
| 0x19                                                     | ReadDTCInformation             | Full        |
| 0x22                                                     | ReadDataByIdentifier           | Full        |
| 0x27                                                     | SecurityAccess                 | Full        |
| 0x29                                                     | Authentication                 | Full        |
| 0x2E                                                     | WriteDataByIdentifier          | Full        |
| 0x2F                                                     | InputOutputControlByIdentifier | Full        |
| 0x31                                                     | RoutineControl                 | Full        |
| 0x3E                                                     | TesterPresent                  | Full        |
| 0x23, 0x24, 0x28, 0x2A, 0x2C, 0x34-0x38, 0x3D, 0x84-0x87 | Other services                 | Enable only |

---

## Negative Response Codes (NRC)

Common NRCs per ISO 14229-1:

| NRC  | Name                                  | Description                             |
| ---- | ------------------------------------- | --------------------------------------- |
| 0x10 | generalReject                         | General reject                          |
| 0x11 | serviceNotSupported                   | Service not supported                   |
| 0x12 | subFunctionNotSupported               | Sub-function not supported              |
| 0x13 | incorrectMessageLengthOrInvalidFormat | Incorrect message length                |
| 0x22 | conditionsNotCorrect                  | Conditions not correct                  |
| 0x24 | requestSequenceError                  | Request sequence error                  |
| 0x31 | requestOutOfRange                     | Request out of range                    |
| 0x33 | securityAccessDenied                  | Security access denied                  |
| 0x35 | invalidKey                            | Invalid key                             |
| 0x36 | exceedNumberOfAttempts                | Exceed number of attempts               |
| 0x37 | requiredTimeDelayNotExpired           | Required time delay not expired         |
| 0x70 | uploadDownloadNotAccepted             | Upload/download not accepted            |
| 0x71 | transferDataSuspended                 | Transfer data suspended                 |
| 0x72 | generalProgrammingFailure             | General programming failure             |
| 0x73 | wrongBlockSequenceCounter             | Wrong block sequence counter            |
| 0x7F | serviceNotSupportedInActiveSession    | Service not supported in active session |
| 0x81 | rpmTooHigh                            | RPM too high                            |
| 0x82 | rpmTooLow                             | RPM too low                             |
| 0x83 | engineIsRunning                       | Engine is running                       |
| 0x84 | engineIsNotRunning                    | Engine is not running                   |
| 0x85 | engineRunTimeTooLow                   | Engine run time too low                 |
| 0x86 | temperatureTooHigh                    | Temperature too high                    |
| 0x87 | temperatureTooLow                     | Temperature too low                     |
| 0x88 | vehicleSpeedTooHigh                   | Vehicle speed too high                  |
| 0x89 | vehicleSpeedTooLow                    | Vehicle speed too low                   |
| 0x92 | voltageTooHigh                        | Voltage too high                        |
| 0x93 | voltageTooLow                         | Voltage too low                         |

---

## Authoring Tips

### `state_model`

- Keep the state space small: session, security and authentication role are usually enough.
- Prefer naming states/levels (e.g., `security: level_01`) rather than encoding raw UDS bytes.

### `variants` + `identification`

- Put complex identification checks into `identification.expected_idents.*`.
- Reference them from variants via `ident_ref`.
- Keep detection rules side-effect free: use `probe_context` instead of assuming a session is already active.

### `response_param_match` and `response_outputs`

To model ODX-like MatchingParameter:
1. Describe a response shape under `services.<svc>.response_outputs` with stable `param_id` values
2. Use either `response_param_match.param_path` (dotted path) or `response_param_match.param_id` (stable identifier)

**Using `param_id` (preferred for deterministic matching):**

```yaml
services:
  readDataByIdentifier:
    enabled: true
    response_outputs:
      hwInfo:
        name: "hwInfo"
        param_id: "HW_INFO"  # Stable identifier
        children:
          - name: "variantCode"
            param_id: "VARIANT_CODE"  # Referenced in response_param_match

identification:
  expected_idents:
    hw_variant_a:
      conditions:
        - response_param_match:
            service: readDataByIdentifier
            param_id: "VARIANT_CODE"  # Use param_id instead of param_path
            expected_value: "VARIANT_A"
```

**Using `param_path` (dotted path notation):**

```yaml
identification:
  expected_idents:
    hw_variant_a:
      conditions:
        - response_param_match:
            service: readDataByIdentifier
            param_path: "hwInfo.variantCode"  # Dotted path
            expected_value: "VARIANT_A"
```

**Rules:**
- Specify exactly one of `param_path` or `param_id` (not both)
- `param_id` must be unique within a service's `response_outputs` (including nested `children`)
- `param_id` is considered stable - changing it is a breaking change

### Metadata blocks

- Use `audience` to express visibility/feature gating in a tool-agnostic way.
- Use `annotations` for simple key/value behavior flags.
- Use `sdgs` when you need hierarchical structured metadata (ODX SDG-like).

### `comparams`

Use `comparams` for protocol/transport parameter sets (DoIP/CAN/UDS/ISO-TP). Each parameter is a single entry with optional metadata and per-protocol values. Use the short form (scalar) for simple parameters without protocol scoping.

### `ecu_jobs`

ECU Jobs define programmed sequences for complex operations:

```yaml
ecu_jobs:
  flash_ecu:
    name: "FlashECU"
    description: "Complete ECU flash programming job"
    prog_code: "FLASH_ECU_V1"
    input_params:
      - name: "flashData"
        type:
          base: bytes
          max_length: 1048576
    output_params:
      - name: "flashStatus"
        type:
          base: u8
    access: "programming_only"
```

### `x-oem`

Use as an escape hatch for vendor-specific data not yet standardized in this schema.
