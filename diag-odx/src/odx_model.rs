//! ODX XML deserialization model.
//!
//! Serde-deserializable types matching ODX 2.2.0 XML structure. Uses quick-xml
//! with `#[serde(rename = "TAG")]` for ODX element names.

use serde::{Deserialize, Serialize};

// --- Root ---

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "ODX")]
pub struct Odx {
    #[serde(rename = "@VERSION", skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(rename = "DIAG-LAYER-CONTAINER", skip_serializing_if = "Option::is_none")]
    pub diag_layer_container: Option<DiagLayerContainer>,
    #[serde(rename = "COMPARAM-SPEC", skip_serializing_if = "Option::is_none")]
    pub comparam_spec: Option<OdxComparamSpec>,
}

// --- DiagLayerContainer ---

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename = "DIAG-LAYER-CONTAINER")]
pub struct DiagLayerContainer {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "ADMIN-DATA", skip_serializing_if = "Option::is_none")]
    pub admin_data: Option<AdminData>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BASE-VARIANTS", skip_serializing_if = "Option::is_none")]
    pub base_variants: Option<BaseVariantsWrapper>,
    #[serde(rename = "ECU-VARIANTS", skip_serializing_if = "Option::is_none")]
    pub ecu_variants: Option<EcuVariantsWrapper>,
    #[serde(rename = "ECU-SHARED-DATAS", skip_serializing_if = "Option::is_none")]
    pub ecu_shared_datas: Option<EcuSharedDatasWrapper>,
    #[serde(rename = "FUNCTIONAL-GROUPS", skip_serializing_if = "Option::is_none")]
    pub functional_groups: Option<FunctionalGroupsWrapper>,
    #[serde(rename = "PROTOCOLS", skip_serializing_if = "Option::is_none")]
    pub protocols: Option<ProtocolsWrapper>,
}

// Wrapper types for list containers
#[derive(Debug, Deserialize, Serialize)]
pub struct BaseVariantsWrapper {
    #[serde(rename = "BASE-VARIANT", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EcuVariantsWrapper {
    #[serde(rename = "ECU-VARIANT", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EcuSharedDatasWrapper {
    #[serde(rename = "ECU-SHARED-DATA", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionalGroupsWrapper {
    #[serde(rename = "FUNCTIONAL-GROUP", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProtocolsWrapper {
    #[serde(rename = "PROTOCOL", default)]
    pub items: Vec<DiagLayerVariant>,
}

// --- DiagLayer (shared across variant types) ---

#[derive(Debug, Deserialize, Serialize)]
pub struct DiagLayerVariant {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "ADMIN-DATA", skip_serializing_if = "Option::is_none")]
    pub admin_data: Option<AdminData>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    // ODX quirk: double-S
    #[serde(rename = "FUNCT-CLASSS", skip_serializing_if = "Option::is_none")]
    pub funct_classs: Option<FunctClasssWrapper>,
    #[serde(rename = "DIAG-DATA-DICTIONARY-SPEC", skip_serializing_if = "Option::is_none")]
    pub diag_data_dictionary_spec: Option<DiagDataDictionarySpec>,
    #[serde(rename = "DIAG-COMMS", skip_serializing_if = "Option::is_none")]
    pub diag_comms: Option<DiagCommsWrapper>,
    #[serde(rename = "REQUESTS", skip_serializing_if = "Option::is_none")]
    pub requests: Option<RequestsWrapper>,
    #[serde(rename = "POS-RESPONSES", skip_serializing_if = "Option::is_none")]
    pub pos_responses: Option<PosResponsesWrapper>,
    #[serde(rename = "NEG-RESPONSES", skip_serializing_if = "Option::is_none")]
    pub neg_responses: Option<NegResponsesWrapper>,
    #[serde(rename = "GLOBAL-NEG-RESPONSES", skip_serializing_if = "Option::is_none")]
    pub global_neg_responses: Option<GlobalNegResponsesWrapper>,
    #[serde(rename = "STATE-CHARTS", skip_serializing_if = "Option::is_none")]
    pub state_charts: Option<StateChartsWrapper>,
    #[serde(rename = "ADDITIONAL-AUDIENCES", skip_serializing_if = "Option::is_none")]
    pub additional_audiences: Option<AdditionalAudiencesWrapper>,
    #[serde(rename = "PARENT-REFS", skip_serializing_if = "Option::is_none")]
    pub parent_refs: Option<ParentRefsWrapper>,
    #[serde(rename = "COMPARAM-REFS", skip_serializing_if = "Option::is_none")]
    pub comparam_refs: Option<ComparamRefsWrapper>,
    #[serde(rename = "ECU-VARIANT-PATTERNS", skip_serializing_if = "Option::is_none")]
    pub ecu_variant_patterns: Option<EcuVariantPatternsWrapper>,
}

// --- List wrappers ---

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctClasssWrapper {
    #[serde(rename = "FUNCT-CLASS", default)]
    pub items: Vec<FunctClass>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DiagCommsWrapper {
    #[serde(rename = "$value", default)]
    pub items: Vec<DiagCommEntry>,
}

/// DiagComms can contain DIAG-SERVICE, SINGLE-ECU-JOB, or DIAG-COMM-REF
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum DiagCommEntry {
    #[serde(rename = "DIAG-SERVICE")]
    DiagService(OdxDiagService),
    #[serde(rename = "SINGLE-ECU-JOB")]
    SingleEcuJob(OdxSingleEcuJob),
    #[serde(rename = "DIAG-COMM-REF")]
    DiagCommRef(OdxRef),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct RequestsWrapper {
    #[serde(rename = "REQUEST", default)]
    pub items: Vec<OdxRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PosResponsesWrapper {
    #[serde(rename = "POS-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NegResponsesWrapper {
    #[serde(rename = "NEG-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GlobalNegResponsesWrapper {
    #[serde(rename = "GLOBAL-NEG-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StateChartsWrapper {
    #[serde(rename = "STATE-CHART", default)]
    pub items: Vec<OdxStateChart>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdditionalAudiencesWrapper {
    #[serde(rename = "ADDITIONAL-AUDIENCE", default)]
    pub items: Vec<OdxAdditionalAudience>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ParentRefsWrapper {
    #[serde(rename = "PARENT-REF", default)]
    pub items: Vec<OdxParentRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ComparamRefsWrapper {
    #[serde(rename = "COMPARAM-REF", default)]
    pub items: Vec<OdxComparamRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EcuVariantPatternsWrapper {
    #[serde(rename = "ECU-VARIANT-PATTERN", default)]
    pub items: Vec<OdxEcuVariantPattern>,
}

// --- DiagService ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDiagService {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "@SEMANTIC", skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
    #[serde(rename = "@DIAGNOSTIC-CLASS", skip_serializing_if = "Option::is_none")]
    pub diagnostic_class: Option<String>,
    #[serde(rename = "@IS-MANDATORY", skip_serializing_if = "Option::is_none")]
    pub is_mandatory: Option<String>,
    #[serde(rename = "@IS-EXECUTABLE", skip_serializing_if = "Option::is_none")]
    pub is_executable: Option<String>,
    #[serde(rename = "@IS-FINAL", skip_serializing_if = "Option::is_none")]
    pub is_final: Option<String>,
    #[serde(rename = "@IS-CYCLIC", skip_serializing_if = "Option::is_none")]
    pub is_cyclic: Option<String>,
    #[serde(rename = "@IS-MULTIPLE", skip_serializing_if = "Option::is_none")]
    pub is_multiple: Option<String>,
    #[serde(rename = "@ADDRESSING", skip_serializing_if = "Option::is_none")]
    pub addressing: Option<String>,
    #[serde(rename = "@TRANSMISSION-MODE", skip_serializing_if = "Option::is_none")]
    pub transmission_mode: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "FUNCT-CLASS-REFS", skip_serializing_if = "Option::is_none")]
    pub funct_class_refs: Option<FunctClassRefsWrapper>,
    #[serde(rename = "AUDIENCE", skip_serializing_if = "Option::is_none")]
    pub audience: Option<OdxAudience>,
    #[serde(rename = "REQUEST-REF", skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<OdxRef>,
    #[serde(rename = "POS-RESPONSE-REFS", skip_serializing_if = "Option::is_none")]
    pub pos_response_refs: Option<PosResponseRefsWrapper>,
    #[serde(rename = "NEG-RESPONSE-REFS", skip_serializing_if = "Option::is_none")]
    pub neg_response_refs: Option<NegResponseRefsWrapper>,
    #[serde(rename = "PRE-CONDITION-STATE-REFS", skip_serializing_if = "Option::is_none")]
    pub pre_condition_state_refs: Option<PreConditionStateRefsWrapper>,
    #[serde(rename = "STATE-TRANSITION-REFS", skip_serializing_if = "Option::is_none")]
    pub state_transition_refs: Option<StateTransitionRefsWrapper>,
    #[serde(rename = "COMPARAM-REFS", skip_serializing_if = "Option::is_none")]
    pub comparam_refs: Option<ComparamRefsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctClassRefsWrapper {
    #[serde(rename = "FUNCT-CLASS-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PosResponseRefsWrapper {
    #[serde(rename = "POS-RESPONSE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NegResponseRefsWrapper {
    #[serde(rename = "NEG-RESPONSE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PreConditionStateRefsWrapper {
    #[serde(rename = "PRE-CONDITION-STATE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StateTransitionRefsWrapper {
    #[serde(rename = "STATE-TRANSITION-REF", default)]
    pub items: Vec<OdxRef>,
}

// --- SingleEcuJob ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxSingleEcuJob {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "PROG-CODES", skip_serializing_if = "Option::is_none")]
    pub prog_codes: Option<ProgCodesWrapper>,
    #[serde(rename = "INPUT-PARAMS", skip_serializing_if = "Option::is_none")]
    pub input_params: Option<InputParamsWrapper>,
    #[serde(rename = "OUTPUT-PARAMS", skip_serializing_if = "Option::is_none")]
    pub output_params: Option<OutputParamsWrapper>,
    #[serde(rename = "NEG-OUTPUT-PARAMS", skip_serializing_if = "Option::is_none")]
    pub neg_output_params: Option<NegOutputParamsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProgCodesWrapper {
    #[serde(rename = "PROG-CODE", default)]
    pub items: Vec<OdxProgCode>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct InputParamsWrapper {
    #[serde(rename = "INPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OutputParamsWrapper {
    #[serde(rename = "OUTPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NegOutputParamsWrapper {
    #[serde(rename = "NEG-OUTPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

// --- Request / Response (basic structures with params) ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxRequest {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BYTE-SIZE", skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS", skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxResponse {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BYTE-SIZE", skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS", skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamsWrapper>,
}

// --- Params ---

#[derive(Debug, Deserialize, Serialize)]
pub struct ParamsWrapper {
    #[serde(rename = "PARAM", default)]
    pub items: Vec<OdxParam>,
}

/// Generic param - uses `xsi:type` attribute for polymorphism.
/// We capture all possible fields and dispatch based on type attr.
#[derive(Debug, Deserialize, Serialize)]
pub struct OdxParam {
    #[serde(rename = "@xsi:type", alias = "@type", skip_serializing_if = "Option::is_none")]
    pub xsi_type: Option<String>,
    #[serde(rename = "@SEMANTIC", skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "BYTE-POSITION", skip_serializing_if = "Option::is_none")]
    pub byte_position: Option<u32>,
    #[serde(rename = "BIT-POSITION", skip_serializing_if = "Option::is_none")]
    pub bit_position: Option<u32>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    // VALUE / PHYS-CONST / SYSTEM / LENGTH-KEY params
    #[serde(rename = "DOP-REF", skip_serializing_if = "Option::is_none")]
    pub dop_ref: Option<OdxRef>,
    #[serde(rename = "DOP-SNREF", skip_serializing_if = "Option::is_none")]
    pub dop_snref: Option<OdxSnRef>,
    #[serde(rename = "PHYSICAL-DEFAULT-VALUE", skip_serializing_if = "Option::is_none")]
    pub physical_default_value: Option<String>,
    // CODED-CONST
    #[serde(rename = "CODED-VALUE", skip_serializing_if = "Option::is_none")]
    pub coded_value: Option<String>,
    #[serde(rename = "DIAG-CODED-TYPE", skip_serializing_if = "Option::is_none")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    // NRC-CONST
    #[serde(rename = "CODED-VALUES", skip_serializing_if = "Option::is_none")]
    pub coded_values: Option<CodedValuesWrapper>,
    // PHYS-CONST
    #[serde(rename = "PHYS-CONSTANT-VALUE", skip_serializing_if = "Option::is_none")]
    pub phys_constant_value: Option<String>,
    // RESERVED
    #[serde(rename = "BIT-LENGTH", skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    // MATCHING-REQUEST-PARAM
    #[serde(rename = "REQUEST-BYTE-POS", skip_serializing_if = "Option::is_none")]
    pub request_byte_pos: Option<i32>,
    #[serde(rename = "MATCH-BYTE-LENGTH", alias = "BYTE-LENGTH", skip_serializing_if = "Option::is_none")]
    pub match_byte_length: Option<u32>,
    // TABLE-KEY
    #[serde(rename = "TABLE-REF", skip_serializing_if = "Option::is_none")]
    pub table_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-SNREF", skip_serializing_if = "Option::is_none")]
    pub table_snref: Option<OdxSnRef>,
    // TABLE-ENTRY
    #[serde(rename = "TARGET", skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(rename = "TABLE-KEY-REF", skip_serializing_if = "Option::is_none")]
    pub table_key_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-KEY-SNREF", skip_serializing_if = "Option::is_none")]
    pub table_key_snref: Option<OdxSnRef>,
    // TABLE-ROW-REF (for TABLE-ENTRY)
    #[serde(rename = "TABLE-ROW-REF", skip_serializing_if = "Option::is_none")]
    pub table_row_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-ROW-SNREF", skip_serializing_if = "Option::is_none")]
    pub table_row_snref: Option<OdxSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CodedValuesWrapper {
    #[serde(rename = "CODED-VALUE", default)]
    pub items: Vec<String>,
}

// --- DiagDataDictionarySpec ---

#[derive(Debug, Deserialize, Serialize)]
pub struct DiagDataDictionarySpec {
    #[serde(rename = "DATA-OBJECT-PROPS", skip_serializing_if = "Option::is_none")]
    pub data_object_props: Option<DataObjectPropsWrapper>,
    #[serde(rename = "DTC-DOPS", skip_serializing_if = "Option::is_none")]
    pub dtc_dops: Option<DtcDopsWrapper>,
    #[serde(rename = "STRUCTURES", skip_serializing_if = "Option::is_none")]
    pub structures: Option<StructuresWrapper>,
    #[serde(rename = "END-OF-PDU-FIELDS", skip_serializing_if = "Option::is_none")]
    pub end_of_pdu_fields: Option<EndOfPduFieldsWrapper>,
    #[serde(rename = "STATIC-FIELDS", skip_serializing_if = "Option::is_none")]
    pub static_fields: Option<StaticFieldsWrapper>,
    #[serde(rename = "DYNAMIC-LENGTH-FIELDS", skip_serializing_if = "Option::is_none")]
    pub dynamic_length_fields: Option<DynamicLengthFieldsWrapper>,
    #[serde(rename = "MUXS", skip_serializing_if = "Option::is_none")]
    pub muxs: Option<MuxsWrapper>,
    #[serde(rename = "ENV-DATAS", skip_serializing_if = "Option::is_none")]
    pub env_datas: Option<EnvDatasWrapper>,
    #[serde(rename = "ENV-DATA-DESCS", skip_serializing_if = "Option::is_none")]
    pub env_data_descs: Option<EnvDataDescsWrapper>,
    #[serde(rename = "TABLES", skip_serializing_if = "Option::is_none")]
    pub tables: Option<TablesWrapper>,
    #[serde(rename = "UNIT-SPEC", skip_serializing_if = "Option::is_none")]
    pub unit_spec: Option<OdxUnitSpec>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
}

// DOP wrappers
#[derive(Debug, Deserialize, Serialize)]
pub struct DataObjectPropsWrapper {
    #[serde(rename = "DATA-OBJECT-PROP", default)]
    pub items: Vec<OdxDataObjectProp>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DtcDopsWrapper {
    #[serde(rename = "DTC-DOP", default)]
    pub items: Vec<OdxDtcDop>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StructuresWrapper {
    #[serde(rename = "STRUCTURE", default)]
    pub items: Vec<OdxStructure>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EndOfPduFieldsWrapper {
    #[serde(rename = "END-OF-PDU-FIELD", default)]
    pub items: Vec<OdxEndOfPduField>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StaticFieldsWrapper {
    #[serde(rename = "STATIC-FIELD", default)]
    pub items: Vec<OdxStaticField>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DynamicLengthFieldsWrapper {
    #[serde(rename = "DYNAMIC-LENGTH-FIELD", default)]
    pub items: Vec<OdxDynamicLengthField>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MuxsWrapper {
    #[serde(rename = "MUX", default)]
    pub items: Vec<OdxMux>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnvDatasWrapper {
    #[serde(rename = "ENV-DATA", default)]
    pub items: Vec<OdxEnvData>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EnvDataDescsWrapper {
    #[serde(rename = "ENV-DATA-DESC", default)]
    pub items: Vec<OdxEnvDataDesc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TablesWrapper {
    #[serde(rename = "TABLE", default)]
    pub items: Vec<OdxTable>,
}

// --- DataObjectProp (DOP) ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDataObjectProp {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "DIAG-CODED-TYPE", skip_serializing_if = "Option::is_none")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    #[serde(rename = "PHYSICAL-TYPE", skip_serializing_if = "Option::is_none")]
    pub physical_type: Option<OdxPhysicalType>,
    #[serde(rename = "COMPU-METHOD", skip_serializing_if = "Option::is_none")]
    pub compu_method: Option<OdxCompuMethod>,
    #[serde(rename = "INTERNAL-CONSTR", skip_serializing_if = "Option::is_none")]
    pub internal_constr: Option<OdxInternalConstr>,
    #[serde(rename = "PHYS-CONSTR", skip_serializing_if = "Option::is_none")]
    pub phys_constr: Option<OdxInternalConstr>,
    #[serde(rename = "UNIT-REF", skip_serializing_if = "Option::is_none")]
    pub unit_ref: Option<OdxRef>,
}

// --- DiagCodedType ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDiagCodedType {
    #[serde(rename = "@xsi:type", alias = "@type", skip_serializing_if = "Option::is_none")]
    pub xsi_type: Option<String>,
    #[serde(rename = "@BASE-DATA-TYPE", skip_serializing_if = "Option::is_none")]
    pub base_data_type: Option<String>,
    #[serde(rename = "@IS-HIGHLOW-BYTE-ORDER", skip_serializing_if = "Option::is_none")]
    pub is_highlow_byte_order: Option<String>,
    #[serde(rename = "@BASE-TYPE-ENCODING", skip_serializing_if = "Option::is_none")]
    pub base_type_encoding: Option<String>,
    #[serde(rename = "@IS-CONDENSED", skip_serializing_if = "Option::is_none")]
    pub is_condensed: Option<String>,
    // Standard length
    #[serde(rename = "BIT-LENGTH", skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    #[serde(rename = "BIT-MASK", skip_serializing_if = "Option::is_none")]
    pub bit_mask: Option<String>,
    // Min-max length
    #[serde(rename = "MIN-LENGTH", skip_serializing_if = "Option::is_none")]
    pub min_length: Option<u32>,
    #[serde(rename = "MAX-LENGTH", skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    #[serde(rename = "TERMINATION", skip_serializing_if = "Option::is_none")]
    pub termination: Option<String>,
    // Param length
    #[serde(rename = "LENGTH-KEY-REF", skip_serializing_if = "Option::is_none")]
    pub length_key_ref: Option<OdxRef>,
}

// --- CompuMethod ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuMethod {
    #[serde(rename = "CATEGORY", skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(rename = "COMPU-INTERNAL-TO-PHYS", skip_serializing_if = "Option::is_none")]
    pub compu_internal_to_phys: Option<OdxCompuInternalToPhys>,
    #[serde(rename = "COMPU-PHYS-TO-INTERNAL", skip_serializing_if = "Option::is_none")]
    pub compu_phys_to_internal: Option<OdxCompuPhysToInternal>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuInternalToPhys {
    #[serde(rename = "COMPU-SCALES", skip_serializing_if = "Option::is_none")]
    pub compu_scales: Option<CompuScalesWrapper>,
    #[serde(rename = "PROG-CODE", skip_serializing_if = "Option::is_none")]
    pub prog_code: Option<OdxProgCode>,
    #[serde(rename = "COMPU-DEFAULT-VALUE", skip_serializing_if = "Option::is_none")]
    pub compu_default_value: Option<OdxCompuDefaultValue>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuPhysToInternal {
    #[serde(rename = "COMPU-SCALES", skip_serializing_if = "Option::is_none")]
    pub compu_scales: Option<CompuScalesWrapper>,
    #[serde(rename = "PROG-CODE", skip_serializing_if = "Option::is_none")]
    pub prog_code: Option<OdxProgCode>,
    #[serde(rename = "COMPU-DEFAULT-VALUE", skip_serializing_if = "Option::is_none")]
    pub compu_default_value: Option<OdxCompuDefaultValue>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CompuScalesWrapper {
    #[serde(rename = "COMPU-SCALE", default)]
    pub items: Vec<OdxCompuScale>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuScale {
    #[serde(rename = "SHORT-LABEL", skip_serializing_if = "Option::is_none")]
    pub short_label: Option<String>,
    #[serde(rename = "LOWER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "COMPU-INVERSE-VALUE", skip_serializing_if = "Option::is_none")]
    pub compu_inverse_value: Option<OdxCompuValues>,
    #[serde(rename = "COMPU-CONST", skip_serializing_if = "Option::is_none")]
    pub compu_const: Option<OdxCompuValues>,
    #[serde(rename = "COMPU-RATIONAL-COEFFS", skip_serializing_if = "Option::is_none")]
    pub compu_rational_coeffs: Option<OdxCompuRationalCoeffs>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxLimit {
    #[serde(rename = "@INTERVAL-TYPE", skip_serializing_if = "Option::is_none")]
    pub interval_type: Option<String>,
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuValues {
    #[serde(rename = "V", skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
    #[serde(rename = "VT", skip_serializing_if = "Option::is_none")]
    pub vt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuRationalCoeffs {
    #[serde(rename = "COMPU-NUMERATOR", skip_serializing_if = "Option::is_none")]
    pub compu_numerator: Option<CompuCoeffsWrapper>,
    #[serde(rename = "COMPU-DENOMINATOR", skip_serializing_if = "Option::is_none")]
    pub compu_denominator: Option<CompuCoeffsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CompuCoeffsWrapper {
    #[serde(rename = "V", default)]
    pub items: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxCompuDefaultValue {
    #[serde(rename = "V", skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
    #[serde(rename = "VT", skip_serializing_if = "Option::is_none")]
    pub vt: Option<String>,
}

// --- PhysicalType ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxPhysicalType {
    #[serde(rename = "@BASE-DATA-TYPE", skip_serializing_if = "Option::is_none")]
    pub base_data_type: Option<String>,
    #[serde(rename = "@DISPLAY-RADIX", skip_serializing_if = "Option::is_none")]
    pub display_radix: Option<String>,
    #[serde(rename = "PRECISION", skip_serializing_if = "Option::is_none")]
    pub precision: Option<u32>,
}

// --- InternalConstr ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxInternalConstr {
    #[serde(rename = "LOWER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "SCALE-CONSTRS", skip_serializing_if = "Option::is_none")]
    pub scale_constrs: Option<ScaleConstrsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScaleConstrsWrapper {
    #[serde(rename = "SCALE-CONSTR", default)]
    pub items: Vec<OdxScaleConstr>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxScaleConstr {
    #[serde(rename = "SHORT-LABEL", skip_serializing_if = "Option::is_none")]
    pub short_label: Option<String>,
    #[serde(rename = "LOWER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT", skip_serializing_if = "Option::is_none")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "VALIDITY", skip_serializing_if = "Option::is_none")]
    pub validity: Option<String>,
}

// --- DTC-DOP ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDtcDop {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "@IS-VISIBLE", skip_serializing_if = "Option::is_none")]
    pub is_visible: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "DIAG-CODED-TYPE", skip_serializing_if = "Option::is_none")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    #[serde(rename = "PHYSICAL-TYPE", skip_serializing_if = "Option::is_none")]
    pub physical_type: Option<OdxPhysicalType>,
    #[serde(rename = "COMPU-METHOD", skip_serializing_if = "Option::is_none")]
    pub compu_method: Option<OdxCompuMethod>,
    #[serde(rename = "DTCS", skip_serializing_if = "Option::is_none")]
    pub dtcs: Option<DtcsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DtcsWrapper {
    #[serde(rename = "DTC", default)]
    pub items: Vec<OdxDtc>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDtc {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "@IS-TEMPORARY", skip_serializing_if = "Option::is_none")]
    pub is_temporary: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "TROUBLE-CODE", skip_serializing_if = "Option::is_none")]
    pub trouble_code: Option<u32>,
    #[serde(rename = "DISPLAY-TROUBLE-CODE", skip_serializing_if = "Option::is_none")]
    pub display_trouble_code: Option<String>,
    #[serde(rename = "TEXT", skip_serializing_if = "Option::is_none")]
    pub text: Option<OdxText>,
    #[serde(rename = "LEVEL", skip_serializing_if = "Option::is_none")]
    pub level: Option<u32>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
}

// --- Structures / Fields ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxStructure {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "BYTE-SIZE", skip_serializing_if = "Option::is_none")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS", skip_serializing_if = "Option::is_none")]
    pub params: Option<ParamsWrapper>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxEndOfPduField {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "MAX-NUMBER-OF-ITEMS", skip_serializing_if = "Option::is_none")]
    pub max_number_of_items: Option<u32>,
    #[serde(rename = "MIN-NUMBER-OF-ITEMS", skip_serializing_if = "Option::is_none")]
    pub min_number_of_items: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxStaticField {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "FIXED-NUMBER-OF-ITEMS", skip_serializing_if = "Option::is_none")]
    pub fixed_number_of_items: Option<u32>,
    #[serde(rename = "ITEM-BYTE-SIZE", skip_serializing_if = "Option::is_none")]
    pub item_byte_size: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxDynamicLengthField {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "OFFSET", skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxMux {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxEnvData {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxEnvDataDesc {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxTable {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "KEY-DOP-REF", skip_serializing_if = "Option::is_none")]
    pub key_dop_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-ROWS", skip_serializing_if = "Option::is_none")]
    pub table_rows: Option<TableRowsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TableRowsWrapper {
    #[serde(rename = "TABLE-ROW", default)]
    pub items: Vec<OdxTableRow>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxTableRow {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "KEY", skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(rename = "STRUCTURE-REF", skip_serializing_if = "Option::is_none")]
    pub structure_ref: Option<OdxRef>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
}

// --- UnitSpec ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxUnitSpec {
    #[serde(rename = "UNITS", skip_serializing_if = "Option::is_none")]
    pub units: Option<UnitsWrapper>,
    #[serde(rename = "PHYSICAL-DIMENSIONS", skip_serializing_if = "Option::is_none")]
    pub physical_dimensions: Option<PhysicalDimensionsWrapper>,
    #[serde(rename = "UNIT-GROUPS", skip_serializing_if = "Option::is_none")]
    pub unit_groups: Option<UnitGroupsWrapper>,
    #[serde(rename = "SDGS", skip_serializing_if = "Option::is_none")]
    pub sdgs: Option<SdgsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnitsWrapper {
    #[serde(rename = "UNIT", default)]
    pub items: Vec<OdxUnit>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxUnit {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "DISPLAY-NAME", skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(rename = "FACTOR-SI-TO-UNIT", skip_serializing_if = "Option::is_none")]
    pub factor_si_to_unit: Option<f64>,
    #[serde(rename = "OFFSET-SI-TO-UNIT", skip_serializing_if = "Option::is_none")]
    pub offset_si_to_unit: Option<f64>,
    #[serde(rename = "PHYSICAL-DIMENSION-REF", skip_serializing_if = "Option::is_none")]
    pub physical_dimension_ref: Option<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PhysicalDimensionsWrapper {
    #[serde(rename = "PHYSICAL-DIMENSION", default)]
    pub items: Vec<OdxPhysicalDimension>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxPhysicalDimension {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LENGTH-EXP", skip_serializing_if = "Option::is_none")]
    pub length_exp: Option<i32>,
    #[serde(rename = "MASS-EXP", skip_serializing_if = "Option::is_none")]
    pub mass_exp: Option<i32>,
    #[serde(rename = "TIME-EXP", skip_serializing_if = "Option::is_none")]
    pub time_exp: Option<i32>,
    #[serde(rename = "CURRENT-EXP", skip_serializing_if = "Option::is_none")]
    pub current_exp: Option<i32>,
    #[serde(rename = "TEMPERATURE-EXP", skip_serializing_if = "Option::is_none")]
    pub temperature_exp: Option<i32>,
    #[serde(rename = "MOLAR-AMOUNT-EXP", skip_serializing_if = "Option::is_none")]
    pub molar_amount_exp: Option<i32>,
    #[serde(rename = "LUMINOUS-INTENSITY-EXP", skip_serializing_if = "Option::is_none")]
    pub luminous_intensity_exp: Option<i32>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnitGroupsWrapper {
    #[serde(rename = "UNIT-GROUP", default)]
    pub items: Vec<OdxUnitGroup>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxUnitGroup {
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
}

// --- StateChart ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxStateChart {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "@SEMANTIC", skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
    #[serde(rename = "START-STATE-SNREF", skip_serializing_if = "Option::is_none")]
    pub start_state_snref: Option<OdxSnRef>,
    #[serde(rename = "STATES", skip_serializing_if = "Option::is_none")]
    pub states: Option<StatesWrapper>,
    #[serde(rename = "STATE-TRANSITIONS", skip_serializing_if = "Option::is_none")]
    pub state_transitions: Option<StateTransitionsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StatesWrapper {
    #[serde(rename = "STATE", default)]
    pub items: Vec<OdxState>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxState {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct StateTransitionsWrapper {
    #[serde(rename = "STATE-TRANSITION", default)]
    pub items: Vec<OdxStateTransition>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxStateTransition {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "SOURCE-SNREF", skip_serializing_if = "Option::is_none")]
    pub source_snref: Option<OdxSnRef>,
    #[serde(rename = "TARGET-SNREF", skip_serializing_if = "Option::is_none")]
    pub target_snref: Option<OdxSnRef>,
}

// --- Audience ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxAudience {
    #[serde(rename = "ENABLED-AUDIENCE-REFS", skip_serializing_if = "Option::is_none")]
    pub enabled_audience_refs: Option<AudienceRefsWrapper>,
    #[serde(rename = "DISABLED-AUDIENCE-REFS", skip_serializing_if = "Option::is_none")]
    pub disabled_audience_refs: Option<AudienceRefsWrapper>,
    #[serde(rename = "@IS-SUPPLIER", skip_serializing_if = "Option::is_none")]
    pub is_supplier: Option<String>,
    #[serde(rename = "@IS-DEVELOPMENT", skip_serializing_if = "Option::is_none")]
    pub is_development: Option<String>,
    #[serde(rename = "@IS-MANUFACTURING", skip_serializing_if = "Option::is_none")]
    pub is_manufacturing: Option<String>,
    #[serde(rename = "@IS-AFTERSALES", skip_serializing_if = "Option::is_none")]
    pub is_aftersales: Option<String>,
    #[serde(rename = "@IS-AFTERMARKET", skip_serializing_if = "Option::is_none")]
    pub is_aftermarket: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AudienceRefsWrapper {
    #[serde(rename = "AUDIENCE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxAdditionalAudience {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
}

// --- ParentRef ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxParentRef {
    #[serde(rename = "@ID-REF", skip_serializing_if = "Option::is_none")]
    pub id_ref: Option<String>,
    #[serde(rename = "@DOCREF", skip_serializing_if = "Option::is_none")]
    pub docref: Option<String>,
    #[serde(rename = "@DOCTYPE", skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
    #[serde(rename = "NOT-INHERITED-DIAG-COMMS", skip_serializing_if = "Option::is_none")]
    pub not_inherited_diag_comms: Option<NotInheritedDiagCommsWrapper>,
    #[serde(rename = "NOT-INHERITED-DOPS", skip_serializing_if = "Option::is_none")]
    pub not_inherited_dops: Option<NotInheritedDopsWrapper>,
    #[serde(rename = "NOT-INHERITED-TABLES", skip_serializing_if = "Option::is_none")]
    pub not_inherited_tables: Option<NotInheritedTablesWrapper>,
    #[serde(rename = "NOT-INHERITED-GLOBAL-NEG-RESPONSES", skip_serializing_if = "Option::is_none")]
    pub not_inherited_global_neg_responses: Option<NotInheritedGlobalNegResponsesWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotInheritedDiagCommsWrapper {
    #[serde(rename = "NOT-INHERITED-DIAG-COMM", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotInheritedDopsWrapper {
    #[serde(rename = "NOT-INHERITED-DOP", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotInheritedTablesWrapper {
    #[serde(rename = "NOT-INHERITED-TABLE", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotInheritedGlobalNegResponsesWrapper {
    #[serde(rename = "NOT-INHERITED-GLOBAL-NEG-RESPONSE", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NotInheritedSnRef {
    #[serde(rename = "DIAG-COMM-SNREF", alias = "DOP-BASE-SNREF", alias = "TABLE-SNREF", alias = "GLOBAL-NEG-RESPONSE-SNREF", skip_serializing_if = "Option::is_none")]
    pub snref: Option<OdxSnRef>,
}

// --- EcuVariantPattern ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxEcuVariantPattern {
    #[serde(rename = "MATCHING-PARAMETERS", skip_serializing_if = "Option::is_none")]
    pub matching_parameters: Option<MatchingParametersWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MatchingParametersWrapper {
    #[serde(rename = "MATCHING-PARAMETER", default)]
    pub items: Vec<OdxMatchingParameter>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxMatchingParameter {
    #[serde(rename = "EXPECTED-VALUE", skip_serializing_if = "Option::is_none")]
    pub expected_value: Option<String>,
    #[serde(rename = "DIAG-COMM-SNREF", skip_serializing_if = "Option::is_none")]
    pub diag_comm_snref: Option<OdxSnRef>,
    #[serde(rename = "OUT-PARAM-SNREF", skip_serializing_if = "Option::is_none")]
    pub out_param_snref: Option<OdxSnRef>,
}

// --- ComparamRef ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxComparamRef {
    #[serde(rename = "@ID-REF", skip_serializing_if = "Option::is_none")]
    pub id_ref: Option<String>,
    #[serde(rename = "SIMPLE-VALUE", skip_serializing_if = "Option::is_none")]
    pub simple_value: Option<String>,
    #[serde(rename = "COMPLEX-VALUE", skip_serializing_if = "Option::is_none")]
    pub complex_value: Option<OdxComplexValue>,
    #[serde(rename = "PROTOCOL-SNREF", skip_serializing_if = "Option::is_none")]
    pub protocol_snref: Option<OdxSnRef>,
    #[serde(rename = "PROT-STACK-SNREF", skip_serializing_if = "Option::is_none")]
    pub prot_stack_snref: Option<OdxSnRef>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxComplexValue {
    #[serde(rename = "SIMPLE-VALUE", default)]
    pub simple_values: Vec<String>,
}

// --- ComparamSpec ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxComparamSpec {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "PROT-STACKS", skip_serializing_if = "Option::is_none")]
    pub prot_stacks: Option<ProtStacksWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProtStacksWrapper {
    #[serde(rename = "PROT-STACK", default)]
    pub items: Vec<OdxProtStack>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxProtStack {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "PDU-PROTOCOL-TYPE", skip_serializing_if = "Option::is_none")]
    pub pdu_protocol_type: Option<String>,
    #[serde(rename = "PHYSICAL-LINK-TYPE", skip_serializing_if = "Option::is_none")]
    pub physical_link_type: Option<String>,
}

// --- ProgCode ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxProgCode {
    #[serde(rename = "CODE-FILE", skip_serializing_if = "Option::is_none")]
    pub code_file: Option<String>,
    #[serde(rename = "ENCRYPTION", skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
    #[serde(rename = "SYNTAX", skip_serializing_if = "Option::is_none")]
    pub syntax: Option<String>,
    #[serde(rename = "REVISION", skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(rename = "ENTRYPOINT", skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,
}

// --- JobParam ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxJobParam {
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
    #[serde(rename = "PHYSICAL-DEFAULT-VALUE", skip_serializing_if = "Option::is_none")]
    pub physical_default_value: Option<String>,
    #[serde(rename = "DOP-BASE-REF", skip_serializing_if = "Option::is_none")]
    pub dop_base_ref: Option<OdxRef>,
    #[serde(rename = "@SEMANTIC", skip_serializing_if = "Option::is_none")]
    pub semantic: Option<String>,
}

// --- Common types ---

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxRef {
    #[serde(rename = "@ID-REF", skip_serializing_if = "Option::is_none")]
    pub id_ref: Option<String>,
    #[serde(rename = "@DOCREF", skip_serializing_if = "Option::is_none")]
    pub docref: Option<String>,
    #[serde(rename = "@DOCTYPE", skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxSnRef {
    #[serde(rename = "@SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxText {
    #[serde(rename = "TI", skip_serializing_if = "Option::is_none")]
    pub ti: Option<String>,
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdminData {
    #[serde(rename = "LANGUAGE", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(rename = "DOC-REVISIONS", skip_serializing_if = "Option::is_none")]
    pub doc_revisions: Option<DocRevisionsWrapper>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DocRevisionsWrapper {
    #[serde(rename = "DOC-REVISION", default)]
    pub items: Vec<DocRevision>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DocRevision {
    #[serde(rename = "REVISION-LABEL", skip_serializing_if = "Option::is_none")]
    pub revision_label: Option<String>,
    #[serde(rename = "STATE", skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "DATE", skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctClass {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME", skip_serializing_if = "Option::is_none")]
    pub long_name: Option<String>,
}

// --- SDGs ---

#[derive(Debug, Deserialize, Serialize)]
pub struct SdgsWrapper {
    #[serde(rename = "SDG", default)]
    pub items: Vec<OdxSdg>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxSdg {
    #[serde(rename = "@GID", skip_serializing_if = "Option::is_none")]
    pub gid: Option<String>,
    #[serde(rename = "@SI", skip_serializing_if = "Option::is_none")]
    pub si: Option<String>,
    #[serde(rename = "SDG-CAPTION", skip_serializing_if = "Option::is_none")]
    pub sdg_caption: Option<OdxSdgCaption>,
    #[serde(rename = "SD", default)]
    pub sds: Vec<OdxSd>,
    #[serde(rename = "SDG", default)]
    pub nested_sdgs: Vec<OdxSdg>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxSdgCaption {
    #[serde(rename = "@ID", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME", skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OdxSd {
    #[serde(rename = "@SI", skip_serializing_if = "Option::is_none")]
    pub si: Option<String>,
    #[serde(rename = "$text", skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}
