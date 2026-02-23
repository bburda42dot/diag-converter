//! ODX XML deserialization model.
//!
//! Serde-deserializable types matching ODX 2.2.0 XML structure. Uses quick-xml
//! with `#[serde(rename = "TAG")]` for ODX element names.

use serde::Deserialize;

// --- Root ---

#[derive(Debug, Deserialize)]
#[serde(rename = "ODX")]
pub struct Odx {
    #[serde(rename = "@VERSION")]
    pub version: Option<String>,
    #[serde(rename = "DIAG-LAYER-CONTAINER")]
    pub diag_layer_container: Option<DiagLayerContainer>,
    #[serde(rename = "COMPARAM-SPEC")]
    pub comparam_spec: Option<OdxComparamSpec>,
}

// --- DiagLayerContainer ---

#[derive(Debug, Deserialize)]
#[serde(rename = "DIAG-LAYER-CONTAINER")]
pub struct DiagLayerContainer {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "ADMIN-DATA")]
    pub admin_data: Option<AdminData>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BASE-VARIANTS")]
    pub base_variants: Option<BaseVariantsWrapper>,
    #[serde(rename = "ECU-VARIANTS")]
    pub ecu_variants: Option<EcuVariantsWrapper>,
    #[serde(rename = "ECU-SHARED-DATAS")]
    pub ecu_shared_datas: Option<EcuSharedDatasWrapper>,
    #[serde(rename = "FUNCTIONAL-GROUPS")]
    pub functional_groups: Option<FunctionalGroupsWrapper>,
    #[serde(rename = "PROTOCOLS")]
    pub protocols: Option<ProtocolsWrapper>,
}

// Wrapper types for list containers
#[derive(Debug, Deserialize)]
pub struct BaseVariantsWrapper {
    #[serde(rename = "BASE-VARIANT", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize)]
pub struct EcuVariantsWrapper {
    #[serde(rename = "ECU-VARIANT", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize)]
pub struct EcuSharedDatasWrapper {
    #[serde(rename = "ECU-SHARED-DATA", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize)]
pub struct FunctionalGroupsWrapper {
    #[serde(rename = "FUNCTIONAL-GROUP", default)]
    pub items: Vec<DiagLayerVariant>,
}

#[derive(Debug, Deserialize)]
pub struct ProtocolsWrapper {
    #[serde(rename = "PROTOCOL", default)]
    pub items: Vec<DiagLayerVariant>,
}

// --- DiagLayer (shared across variant types) ---

#[derive(Debug, Deserialize)]
pub struct DiagLayerVariant {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "ADMIN-DATA")]
    pub admin_data: Option<AdminData>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    // ODX quirk: double-S
    #[serde(rename = "FUNCT-CLASSS")]
    pub funct_classs: Option<FunctClasssWrapper>,
    #[serde(rename = "DIAG-DATA-DICTIONARY-SPEC")]
    pub diag_data_dictionary_spec: Option<DiagDataDictionarySpec>,
    #[serde(rename = "DIAG-COMMS")]
    pub diag_comms: Option<DiagCommsWrapper>,
    #[serde(rename = "REQUESTS")]
    pub requests: Option<RequestsWrapper>,
    #[serde(rename = "POS-RESPONSES")]
    pub pos_responses: Option<PosResponsesWrapper>,
    #[serde(rename = "NEG-RESPONSES")]
    pub neg_responses: Option<NegResponsesWrapper>,
    #[serde(rename = "GLOBAL-NEG-RESPONSES")]
    pub global_neg_responses: Option<GlobalNegResponsesWrapper>,
    #[serde(rename = "STATE-CHARTS")]
    pub state_charts: Option<StateChartsWrapper>,
    #[serde(rename = "ADDITIONAL-AUDIENCES")]
    pub additional_audiences: Option<AdditionalAudiencesWrapper>,
    #[serde(rename = "PARENT-REFS")]
    pub parent_refs: Option<ParentRefsWrapper>,
    #[serde(rename = "COMPARAM-REFS")]
    pub comparam_refs: Option<ComparamRefsWrapper>,
    #[serde(rename = "ECU-VARIANT-PATTERNS")]
    pub ecu_variant_patterns: Option<EcuVariantPatternsWrapper>,
}

// --- List wrappers ---

#[derive(Debug, Deserialize)]
pub struct FunctClasssWrapper {
    #[serde(rename = "FUNCT-CLASS", default)]
    pub items: Vec<FunctClass>,
}

#[derive(Debug, Deserialize)]
pub struct DiagCommsWrapper {
    #[serde(rename = "$value", default)]
    pub items: Vec<DiagCommEntry>,
}

/// DiagComms can contain DIAG-SERVICE, SINGLE-ECU-JOB, or DIAG-COMM-REF
#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING-KEBAB-CASE")]
pub enum DiagCommEntry {
    #[serde(rename = "DIAG-SERVICE")]
    DiagService(OdxDiagService),
    #[serde(rename = "SINGLE-ECU-JOB")]
    SingleEcuJob(OdxSingleEcuJob),
    #[serde(rename = "DIAG-COMM-REF")]
    DiagCommRef(OdxRef),
}

#[derive(Debug, Deserialize)]
pub struct RequestsWrapper {
    #[serde(rename = "REQUEST", default)]
    pub items: Vec<OdxRequest>,
}

#[derive(Debug, Deserialize)]
pub struct PosResponsesWrapper {
    #[serde(rename = "POS-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize)]
pub struct NegResponsesWrapper {
    #[serde(rename = "NEG-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize)]
pub struct GlobalNegResponsesWrapper {
    #[serde(rename = "GLOBAL-NEG-RESPONSE", default)]
    pub items: Vec<OdxResponse>,
}

#[derive(Debug, Deserialize)]
pub struct StateChartsWrapper {
    #[serde(rename = "STATE-CHART", default)]
    pub items: Vec<OdxStateChart>,
}

#[derive(Debug, Deserialize)]
pub struct AdditionalAudiencesWrapper {
    #[serde(rename = "ADDITIONAL-AUDIENCE", default)]
    pub items: Vec<OdxAdditionalAudience>,
}

#[derive(Debug, Deserialize)]
pub struct ParentRefsWrapper {
    #[serde(rename = "PARENT-REF", default)]
    pub items: Vec<OdxParentRef>,
}

#[derive(Debug, Deserialize)]
pub struct ComparamRefsWrapper {
    #[serde(rename = "COMPARAM-REF", default)]
    pub items: Vec<OdxComparamRef>,
}

#[derive(Debug, Deserialize)]
pub struct EcuVariantPatternsWrapper {
    #[serde(rename = "ECU-VARIANT-PATTERN", default)]
    pub items: Vec<OdxEcuVariantPattern>,
}

// --- DiagService ---

#[derive(Debug, Deserialize)]
pub struct OdxDiagService {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@SEMANTIC")]
    pub semantic: Option<String>,
    #[serde(rename = "@DIAGNOSTIC-CLASS")]
    pub diagnostic_class: Option<String>,
    #[serde(rename = "@IS-MANDATORY")]
    pub is_mandatory: Option<String>,
    #[serde(rename = "@IS-EXECUTABLE")]
    pub is_executable: Option<String>,
    #[serde(rename = "@IS-FINAL")]
    pub is_final: Option<String>,
    #[serde(rename = "@IS-CYCLIC")]
    pub is_cyclic: Option<String>,
    #[serde(rename = "@IS-MULTIPLE")]
    pub is_multiple: Option<String>,
    #[serde(rename = "@ADDRESSING")]
    pub addressing: Option<String>,
    #[serde(rename = "@TRANSMISSION-MODE")]
    pub transmission_mode: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "FUNCT-CLASS-REFS")]
    pub funct_class_refs: Option<FunctClassRefsWrapper>,
    #[serde(rename = "AUDIENCE")]
    pub audience: Option<OdxAudience>,
    #[serde(rename = "REQUEST-REF")]
    pub request_ref: Option<OdxRef>,
    #[serde(rename = "POS-RESPONSE-REFS")]
    pub pos_response_refs: Option<PosResponseRefsWrapper>,
    #[serde(rename = "NEG-RESPONSE-REFS")]
    pub neg_response_refs: Option<NegResponseRefsWrapper>,
    #[serde(rename = "PRE-CONDITION-STATE-REFS")]
    pub pre_condition_state_refs: Option<PreConditionStateRefsWrapper>,
    #[serde(rename = "STATE-TRANSITION-REFS")]
    pub state_transition_refs: Option<StateTransitionRefsWrapper>,
    #[serde(rename = "COMPARAM-REFS")]
    pub comparam_refs: Option<ComparamRefsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct FunctClassRefsWrapper {
    #[serde(rename = "FUNCT-CLASS-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct PosResponseRefsWrapper {
    #[serde(rename = "POS-RESPONSE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct NegResponseRefsWrapper {
    #[serde(rename = "NEG-RESPONSE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct PreConditionStateRefsWrapper {
    #[serde(rename = "PRE-CONDITION-STATE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct StateTransitionRefsWrapper {
    #[serde(rename = "STATE-TRANSITION-REF", default)]
    pub items: Vec<OdxRef>,
}

// --- SingleEcuJob ---

#[derive(Debug, Deserialize)]
pub struct OdxSingleEcuJob {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "PROG-CODES")]
    pub prog_codes: Option<ProgCodesWrapper>,
    #[serde(rename = "INPUT-PARAMS")]
    pub input_params: Option<InputParamsWrapper>,
    #[serde(rename = "OUTPUT-PARAMS")]
    pub output_params: Option<OutputParamsWrapper>,
    #[serde(rename = "NEG-OUTPUT-PARAMS")]
    pub neg_output_params: Option<NegOutputParamsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct ProgCodesWrapper {
    #[serde(rename = "PROG-CODE", default)]
    pub items: Vec<OdxProgCode>,
}

#[derive(Debug, Deserialize)]
pub struct InputParamsWrapper {
    #[serde(rename = "INPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

#[derive(Debug, Deserialize)]
pub struct OutputParamsWrapper {
    #[serde(rename = "OUTPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

#[derive(Debug, Deserialize)]
pub struct NegOutputParamsWrapper {
    #[serde(rename = "NEG-OUTPUT-PARAM", default)]
    pub items: Vec<OdxJobParam>,
}

// --- Request / Response (basic structures with params) ---

#[derive(Debug, Deserialize)]
pub struct OdxRequest {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BYTE-SIZE")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS")]
    pub params: Option<ParamsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct OdxResponse {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "BYTE-SIZE")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS")]
    pub params: Option<ParamsWrapper>,
}

// --- Params ---

#[derive(Debug, Deserialize)]
pub struct ParamsWrapper {
    #[serde(rename = "PARAM", default)]
    pub items: Vec<OdxParam>,
}

/// Generic param - uses `xsi:type` attribute for polymorphism.
/// We capture all possible fields and dispatch based on type attr.
#[derive(Debug, Deserialize)]
pub struct OdxParam {
    #[serde(rename = "@xsi:type", alias = "@type")]
    pub xsi_type: Option<String>,
    #[serde(rename = "@SEMANTIC")]
    pub semantic: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "BYTE-POSITION")]
    pub byte_position: Option<u32>,
    #[serde(rename = "BIT-POSITION")]
    pub bit_position: Option<u32>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    // VALUE / PHYS-CONST / SYSTEM / LENGTH-KEY params
    #[serde(rename = "DOP-REF")]
    pub dop_ref: Option<OdxRef>,
    #[serde(rename = "DOP-SNREF")]
    pub dop_snref: Option<OdxSnRef>,
    #[serde(rename = "PHYSICAL-DEFAULT-VALUE")]
    pub physical_default_value: Option<String>,
    // CODED-CONST
    #[serde(rename = "CODED-VALUE")]
    pub coded_value: Option<String>,
    #[serde(rename = "DIAG-CODED-TYPE")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    // NRC-CONST
    #[serde(rename = "CODED-VALUES")]
    pub coded_values: Option<CodedValuesWrapper>,
    // PHYS-CONST
    #[serde(rename = "PHYS-CONSTANT-VALUE")]
    pub phys_constant_value: Option<String>,
    // RESERVED
    #[serde(rename = "BIT-LENGTH")]
    pub bit_length: Option<u32>,
    // MATCHING-REQUEST-PARAM
    #[serde(rename = "REQUEST-BYTE-POS")]
    pub request_byte_pos: Option<i32>,
    #[serde(rename = "MATCH-BYTE-LENGTH", alias = "BYTE-LENGTH")]
    pub match_byte_length: Option<u32>,
    // TABLE-KEY
    #[serde(rename = "TABLE-REF")]
    pub table_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-SNREF")]
    pub table_snref: Option<OdxSnRef>,
    // TABLE-ENTRY
    #[serde(rename = "TARGET")]
    pub target: Option<String>,
    #[serde(rename = "TABLE-KEY-REF")]
    pub table_key_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-KEY-SNREF")]
    pub table_key_snref: Option<OdxSnRef>,
    // TABLE-ROW-REF (for TABLE-ENTRY)
    #[serde(rename = "TABLE-ROW-REF")]
    pub table_row_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-ROW-SNREF")]
    pub table_row_snref: Option<OdxSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct CodedValuesWrapper {
    #[serde(rename = "CODED-VALUE", default)]
    pub items: Vec<String>,
}

// --- DiagDataDictionarySpec ---

#[derive(Debug, Deserialize)]
pub struct DiagDataDictionarySpec {
    #[serde(rename = "DATA-OBJECT-PROPS")]
    pub data_object_props: Option<DataObjectPropsWrapper>,
    #[serde(rename = "DTC-DOPS")]
    pub dtc_dops: Option<DtcDopsWrapper>,
    #[serde(rename = "STRUCTURES")]
    pub structures: Option<StructuresWrapper>,
    #[serde(rename = "END-OF-PDU-FIELDS")]
    pub end_of_pdu_fields: Option<EndOfPduFieldsWrapper>,
    #[serde(rename = "STATIC-FIELDS")]
    pub static_fields: Option<StaticFieldsWrapper>,
    #[serde(rename = "DYNAMIC-LENGTH-FIELDS")]
    pub dynamic_length_fields: Option<DynamicLengthFieldsWrapper>,
    #[serde(rename = "MUXS")]
    pub muxs: Option<MuxsWrapper>,
    #[serde(rename = "ENV-DATAS")]
    pub env_datas: Option<EnvDatasWrapper>,
    #[serde(rename = "ENV-DATA-DESCS")]
    pub env_data_descs: Option<EnvDataDescsWrapper>,
    #[serde(rename = "TABLES")]
    pub tables: Option<TablesWrapper>,
    #[serde(rename = "UNIT-SPEC")]
    pub unit_spec: Option<OdxUnitSpec>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
}

// DOP wrappers
#[derive(Debug, Deserialize)]
pub struct DataObjectPropsWrapper {
    #[serde(rename = "DATA-OBJECT-PROP", default)]
    pub items: Vec<OdxDataObjectProp>,
}

#[derive(Debug, Deserialize)]
pub struct DtcDopsWrapper {
    #[serde(rename = "DTC-DOP", default)]
    pub items: Vec<OdxDtcDop>,
}

#[derive(Debug, Deserialize)]
pub struct StructuresWrapper {
    #[serde(rename = "STRUCTURE", default)]
    pub items: Vec<OdxStructure>,
}

#[derive(Debug, Deserialize)]
pub struct EndOfPduFieldsWrapper {
    #[serde(rename = "END-OF-PDU-FIELD", default)]
    pub items: Vec<OdxEndOfPduField>,
}

#[derive(Debug, Deserialize)]
pub struct StaticFieldsWrapper {
    #[serde(rename = "STATIC-FIELD", default)]
    pub items: Vec<OdxStaticField>,
}

#[derive(Debug, Deserialize)]
pub struct DynamicLengthFieldsWrapper {
    #[serde(rename = "DYNAMIC-LENGTH-FIELD", default)]
    pub items: Vec<OdxDynamicLengthField>,
}

#[derive(Debug, Deserialize)]
pub struct MuxsWrapper {
    #[serde(rename = "MUX", default)]
    pub items: Vec<OdxMux>,
}

#[derive(Debug, Deserialize)]
pub struct EnvDatasWrapper {
    #[serde(rename = "ENV-DATA", default)]
    pub items: Vec<OdxEnvData>,
}

#[derive(Debug, Deserialize)]
pub struct EnvDataDescsWrapper {
    #[serde(rename = "ENV-DATA-DESC", default)]
    pub items: Vec<OdxEnvDataDesc>,
}

#[derive(Debug, Deserialize)]
pub struct TablesWrapper {
    #[serde(rename = "TABLE", default)]
    pub items: Vec<OdxTable>,
}

// --- DataObjectProp (DOP) ---

#[derive(Debug, Deserialize)]
pub struct OdxDataObjectProp {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "DIAG-CODED-TYPE")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    #[serde(rename = "PHYSICAL-TYPE")]
    pub physical_type: Option<OdxPhysicalType>,
    #[serde(rename = "COMPU-METHOD")]
    pub compu_method: Option<OdxCompuMethod>,
    #[serde(rename = "INTERNAL-CONSTR")]
    pub internal_constr: Option<OdxInternalConstr>,
    #[serde(rename = "PHYS-CONSTR")]
    pub phys_constr: Option<OdxInternalConstr>,
    #[serde(rename = "UNIT-REF")]
    pub unit_ref: Option<OdxRef>,
}

// --- DiagCodedType ---

#[derive(Debug, Deserialize)]
pub struct OdxDiagCodedType {
    #[serde(rename = "@xsi:type", alias = "@type")]
    pub xsi_type: Option<String>,
    #[serde(rename = "@BASE-DATA-TYPE")]
    pub base_data_type: Option<String>,
    #[serde(rename = "@IS-HIGHLOW-BYTE-ORDER")]
    pub is_highlow_byte_order: Option<String>,
    #[serde(rename = "@BASE-TYPE-ENCODING")]
    pub base_type_encoding: Option<String>,
    #[serde(rename = "@IS-CONDENSED")]
    pub is_condensed: Option<String>,
    // Standard length
    #[serde(rename = "BIT-LENGTH")]
    pub bit_length: Option<u32>,
    #[serde(rename = "BIT-MASK")]
    pub bit_mask: Option<String>,
    // Min-max length
    #[serde(rename = "MIN-LENGTH")]
    pub min_length: Option<u32>,
    #[serde(rename = "MAX-LENGTH")]
    pub max_length: Option<u32>,
    #[serde(rename = "TERMINATION")]
    pub termination: Option<String>,
    // Param length
    #[serde(rename = "LENGTH-KEY-REF")]
    pub length_key_ref: Option<OdxRef>,
}

// --- CompuMethod ---

#[derive(Debug, Deserialize)]
pub struct OdxCompuMethod {
    #[serde(rename = "CATEGORY")]
    pub category: Option<String>,
    #[serde(rename = "COMPU-INTERNAL-TO-PHYS")]
    pub compu_internal_to_phys: Option<OdxCompuInternalToPhys>,
    #[serde(rename = "COMPU-PHYS-TO-INTERNAL")]
    pub compu_phys_to_internal: Option<OdxCompuPhysToInternal>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuInternalToPhys {
    #[serde(rename = "COMPU-SCALES")]
    pub compu_scales: Option<CompuScalesWrapper>,
    #[serde(rename = "PROG-CODE")]
    pub prog_code: Option<OdxProgCode>,
    #[serde(rename = "COMPU-DEFAULT-VALUE")]
    pub compu_default_value: Option<OdxCompuDefaultValue>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuPhysToInternal {
    #[serde(rename = "COMPU-SCALES")]
    pub compu_scales: Option<CompuScalesWrapper>,
    #[serde(rename = "PROG-CODE")]
    pub prog_code: Option<OdxProgCode>,
    #[serde(rename = "COMPU-DEFAULT-VALUE")]
    pub compu_default_value: Option<OdxCompuDefaultValue>,
}

#[derive(Debug, Deserialize)]
pub struct CompuScalesWrapper {
    #[serde(rename = "COMPU-SCALE", default)]
    pub items: Vec<OdxCompuScale>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuScale {
    #[serde(rename = "SHORT-LABEL")]
    pub short_label: Option<String>,
    #[serde(rename = "LOWER-LIMIT")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "COMPU-INVERSE-VALUE")]
    pub compu_inverse_value: Option<OdxCompuValues>,
    #[serde(rename = "COMPU-CONST")]
    pub compu_const: Option<OdxCompuValues>,
    #[serde(rename = "COMPU-RATIONAL-COEFFS")]
    pub compu_rational_coeffs: Option<OdxCompuRationalCoeffs>,
}

#[derive(Debug, Deserialize)]
pub struct OdxLimit {
    #[serde(rename = "@INTERVAL-TYPE")]
    pub interval_type: Option<String>,
    #[serde(rename = "$text")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuValues {
    #[serde(rename = "V")]
    pub v: Option<String>,
    #[serde(rename = "VT")]
    pub vt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuRationalCoeffs {
    #[serde(rename = "COMPU-NUMERATOR")]
    pub compu_numerator: Option<CompuCoeffsWrapper>,
    #[serde(rename = "COMPU-DENOMINATOR")]
    pub compu_denominator: Option<CompuCoeffsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct CompuCoeffsWrapper {
    #[serde(rename = "V", default)]
    pub items: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxCompuDefaultValue {
    #[serde(rename = "V")]
    pub v: Option<String>,
    #[serde(rename = "VT")]
    pub vt: Option<String>,
}

// --- PhysicalType ---

#[derive(Debug, Deserialize)]
pub struct OdxPhysicalType {
    #[serde(rename = "@BASE-DATA-TYPE")]
    pub base_data_type: Option<String>,
    #[serde(rename = "@DISPLAY-RADIX")]
    pub display_radix: Option<String>,
    #[serde(rename = "PRECISION")]
    pub precision: Option<u32>,
}

// --- InternalConstr ---

#[derive(Debug, Deserialize)]
pub struct OdxInternalConstr {
    #[serde(rename = "LOWER-LIMIT")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "SCALE-CONSTRS")]
    pub scale_constrs: Option<ScaleConstrsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct ScaleConstrsWrapper {
    #[serde(rename = "SCALE-CONSTR", default)]
    pub items: Vec<OdxScaleConstr>,
}

#[derive(Debug, Deserialize)]
pub struct OdxScaleConstr {
    #[serde(rename = "SHORT-LABEL")]
    pub short_label: Option<String>,
    #[serde(rename = "LOWER-LIMIT")]
    pub lower_limit: Option<OdxLimit>,
    #[serde(rename = "UPPER-LIMIT")]
    pub upper_limit: Option<OdxLimit>,
    #[serde(rename = "VALIDITY")]
    pub validity: Option<String>,
}

// --- DTC-DOP ---

#[derive(Debug, Deserialize)]
pub struct OdxDtcDop {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@IS-VISIBLE")]
    pub is_visible: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "DIAG-CODED-TYPE")]
    pub diag_coded_type: Option<OdxDiagCodedType>,
    #[serde(rename = "PHYSICAL-TYPE")]
    pub physical_type: Option<OdxPhysicalType>,
    #[serde(rename = "COMPU-METHOD")]
    pub compu_method: Option<OdxCompuMethod>,
    #[serde(rename = "DTCS")]
    pub dtcs: Option<DtcsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct DtcsWrapper {
    #[serde(rename = "DTC", default)]
    pub items: Vec<OdxDtc>,
}

#[derive(Debug, Deserialize)]
pub struct OdxDtc {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@IS-TEMPORARY")]
    pub is_temporary: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "TROUBLE-CODE")]
    pub trouble_code: Option<u32>,
    #[serde(rename = "DISPLAY-TROUBLE-CODE")]
    pub display_trouble_code: Option<String>,
    #[serde(rename = "TEXT")]
    pub text: Option<OdxText>,
    #[serde(rename = "LEVEL")]
    pub level: Option<u32>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
}

// --- Structures / Fields ---

#[derive(Debug, Deserialize)]
pub struct OdxStructure {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "BYTE-SIZE")]
    pub byte_size: Option<u32>,
    #[serde(rename = "PARAMS")]
    pub params: Option<ParamsWrapper>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct OdxEndOfPduField {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "MAX-NUMBER-OF-ITEMS")]
    pub max_number_of_items: Option<u32>,
    #[serde(rename = "MIN-NUMBER-OF-ITEMS")]
    pub min_number_of_items: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OdxStaticField {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "FIXED-NUMBER-OF-ITEMS")]
    pub fixed_number_of_items: Option<u32>,
    #[serde(rename = "ITEM-BYTE-SIZE")]
    pub item_byte_size: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OdxDynamicLengthField {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "OFFSET")]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct OdxMux {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxEnvData {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxEnvDataDesc {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxTable {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
    #[serde(rename = "KEY-DOP-REF")]
    pub key_dop_ref: Option<OdxRef>,
    #[serde(rename = "TABLE-ROWS")]
    pub table_rows: Option<TableRowsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct TableRowsWrapper {
    #[serde(rename = "TABLE-ROW", default)]
    pub items: Vec<OdxTableRow>,
}

#[derive(Debug, Deserialize)]
pub struct OdxTableRow {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "KEY")]
    pub key: Option<String>,
    #[serde(rename = "STRUCTURE-REF")]
    pub structure_ref: Option<OdxRef>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
}

// --- UnitSpec ---

#[derive(Debug, Deserialize)]
pub struct OdxUnitSpec {
    #[serde(rename = "UNITS")]
    pub units: Option<UnitsWrapper>,
    #[serde(rename = "PHYSICAL-DIMENSIONS")]
    pub physical_dimensions: Option<PhysicalDimensionsWrapper>,
    #[serde(rename = "UNIT-GROUPS")]
    pub unit_groups: Option<UnitGroupsWrapper>,
    #[serde(rename = "SDGS")]
    pub sdgs: Option<SdgsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct UnitsWrapper {
    #[serde(rename = "UNIT", default)]
    pub items: Vec<OdxUnit>,
}

#[derive(Debug, Deserialize)]
pub struct OdxUnit {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "DISPLAY-NAME")]
    pub display_name: Option<String>,
    #[serde(rename = "FACTOR-SI-TO-UNIT")]
    pub factor_si_to_unit: Option<f64>,
    #[serde(rename = "OFFSET-SI-TO-UNIT")]
    pub offset_si_to_unit: Option<f64>,
    #[serde(rename = "PHYSICAL-DIMENSION-REF")]
    pub physical_dimension_ref: Option<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct PhysicalDimensionsWrapper {
    #[serde(rename = "PHYSICAL-DIMENSION", default)]
    pub items: Vec<OdxPhysicalDimension>,
}

#[derive(Debug, Deserialize)]
pub struct OdxPhysicalDimension {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LENGTH-EXP")]
    pub length_exp: Option<i32>,
    #[serde(rename = "MASS-EXP")]
    pub mass_exp: Option<i32>,
    #[serde(rename = "TIME-EXP")]
    pub time_exp: Option<i32>,
    #[serde(rename = "CURRENT-EXP")]
    pub current_exp: Option<i32>,
    #[serde(rename = "TEMPERATURE-EXP")]
    pub temperature_exp: Option<i32>,
    #[serde(rename = "MOLAR-AMOUNT-EXP")]
    pub molar_amount_exp: Option<i32>,
    #[serde(rename = "LUMINOUS-INTENSITY-EXP")]
    pub luminous_intensity_exp: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UnitGroupsWrapper {
    #[serde(rename = "UNIT-GROUP", default)]
    pub items: Vec<OdxUnitGroup>,
}

#[derive(Debug, Deserialize)]
pub struct OdxUnitGroup {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
}

// --- StateChart ---

#[derive(Debug, Deserialize)]
pub struct OdxStateChart {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "@SEMANTIC")]
    pub semantic: Option<String>,
    #[serde(rename = "START-STATE-SNREF")]
    pub start_state_snref: Option<OdxSnRef>,
    #[serde(rename = "STATES")]
    pub states: Option<StatesWrapper>,
    #[serde(rename = "STATE-TRANSITIONS")]
    pub state_transitions: Option<StateTransitionsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct StatesWrapper {
    #[serde(rename = "STATE", default)]
    pub items: Vec<OdxState>,
}

#[derive(Debug, Deserialize)]
pub struct OdxState {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StateTransitionsWrapper {
    #[serde(rename = "STATE-TRANSITION", default)]
    pub items: Vec<OdxStateTransition>,
}

#[derive(Debug, Deserialize)]
pub struct OdxStateTransition {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "SOURCE-SNREF")]
    pub source_snref: Option<OdxSnRef>,
    #[serde(rename = "TARGET-SNREF")]
    pub target_snref: Option<OdxSnRef>,
}

// --- Audience ---

#[derive(Debug, Deserialize)]
pub struct OdxAudience {
    #[serde(rename = "ENABLED-AUDIENCE-REFS")]
    pub enabled_audience_refs: Option<AudienceRefsWrapper>,
    #[serde(rename = "DISABLED-AUDIENCE-REFS")]
    pub disabled_audience_refs: Option<AudienceRefsWrapper>,
    #[serde(rename = "@IS-SUPPLIER")]
    pub is_supplier: Option<String>,
    #[serde(rename = "@IS-DEVELOPMENT")]
    pub is_development: Option<String>,
    #[serde(rename = "@IS-MANUFACTURING")]
    pub is_manufacturing: Option<String>,
    #[serde(rename = "@IS-AFTERSALES")]
    pub is_aftersales: Option<String>,
    #[serde(rename = "@IS-AFTERMARKET")]
    pub is_aftermarket: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AudienceRefsWrapper {
    #[serde(rename = "AUDIENCE-REF", default)]
    pub items: Vec<OdxRef>,
}

#[derive(Debug, Deserialize)]
pub struct OdxAdditionalAudience {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
}

// --- ParentRef ---

#[derive(Debug, Deserialize)]
pub struct OdxParentRef {
    #[serde(rename = "@ID-REF")]
    pub id_ref: Option<String>,
    #[serde(rename = "@DOCREF")]
    pub docref: Option<String>,
    #[serde(rename = "@DOCTYPE")]
    pub doctype: Option<String>,
    #[serde(rename = "NOT-INHERITED-DIAG-COMMS")]
    pub not_inherited_diag_comms: Option<NotInheritedDiagCommsWrapper>,
    #[serde(rename = "NOT-INHERITED-DOPS")]
    pub not_inherited_dops: Option<NotInheritedDopsWrapper>,
    #[serde(rename = "NOT-INHERITED-TABLES")]
    pub not_inherited_tables: Option<NotInheritedTablesWrapper>,
    #[serde(rename = "NOT-INHERITED-GLOBAL-NEG-RESPONSES")]
    pub not_inherited_global_neg_responses: Option<NotInheritedGlobalNegResponsesWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct NotInheritedDiagCommsWrapper {
    #[serde(rename = "NOT-INHERITED-DIAG-COMM", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct NotInheritedDopsWrapper {
    #[serde(rename = "NOT-INHERITED-DOP", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct NotInheritedTablesWrapper {
    #[serde(rename = "NOT-INHERITED-TABLE", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct NotInheritedGlobalNegResponsesWrapper {
    #[serde(rename = "NOT-INHERITED-GLOBAL-NEG-RESPONSE", default)]
    pub items: Vec<NotInheritedSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct NotInheritedSnRef {
    #[serde(rename = "DIAG-COMM-SNREF", alias = "DOP-BASE-SNREF", alias = "TABLE-SNREF", alias = "GLOBAL-NEG-RESPONSE-SNREF")]
    pub snref: Option<OdxSnRef>,
}

// --- EcuVariantPattern ---

#[derive(Debug, Deserialize)]
pub struct OdxEcuVariantPattern {
    #[serde(rename = "MATCHING-PARAMETERS")]
    pub matching_parameters: Option<MatchingParametersWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct MatchingParametersWrapper {
    #[serde(rename = "MATCHING-PARAMETER", default)]
    pub items: Vec<OdxMatchingParameter>,
}

#[derive(Debug, Deserialize)]
pub struct OdxMatchingParameter {
    #[serde(rename = "EXPECTED-VALUE")]
    pub expected_value: Option<String>,
    #[serde(rename = "DIAG-COMM-SNREF")]
    pub diag_comm_snref: Option<OdxSnRef>,
    #[serde(rename = "OUT-PARAM-SNREF")]
    pub out_param_snref: Option<OdxSnRef>,
}

// --- ComparamRef ---

#[derive(Debug, Deserialize)]
pub struct OdxComparamRef {
    #[serde(rename = "@ID-REF")]
    pub id_ref: Option<String>,
    #[serde(rename = "SIMPLE-VALUE")]
    pub simple_value: Option<String>,
    #[serde(rename = "COMPLEX-VALUE")]
    pub complex_value: Option<OdxComplexValue>,
    #[serde(rename = "PROTOCOL-SNREF")]
    pub protocol_snref: Option<OdxSnRef>,
    #[serde(rename = "PROT-STACK-SNREF")]
    pub prot_stack_snref: Option<OdxSnRef>,
}

#[derive(Debug, Deserialize)]
pub struct OdxComplexValue {
    #[serde(rename = "SIMPLE-VALUE", default)]
    pub simple_values: Vec<String>,
}

// --- ComparamSpec ---

#[derive(Debug, Deserialize)]
pub struct OdxComparamSpec {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "PROT-STACKS")]
    pub prot_stacks: Option<ProtStacksWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct ProtStacksWrapper {
    #[serde(rename = "PROT-STACK", default)]
    pub items: Vec<OdxProtStack>,
}

#[derive(Debug, Deserialize)]
pub struct OdxProtStack {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "PDU-PROTOCOL-TYPE")]
    pub pdu_protocol_type: Option<String>,
    #[serde(rename = "PHYSICAL-LINK-TYPE")]
    pub physical_link_type: Option<String>,
}

// --- ProgCode ---

#[derive(Debug, Deserialize)]
pub struct OdxProgCode {
    #[serde(rename = "CODE-FILE")]
    pub code_file: Option<String>,
    #[serde(rename = "ENCRYPTION")]
    pub encryption: Option<String>,
    #[serde(rename = "SYNTAX")]
    pub syntax: Option<String>,
    #[serde(rename = "REVISION")]
    pub revision: Option<String>,
    #[serde(rename = "ENTRYPOINT")]
    pub entrypoint: Option<String>,
}

// --- JobParam ---

#[derive(Debug, Deserialize)]
pub struct OdxJobParam {
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
    #[serde(rename = "PHYSICAL-DEFAULT-VALUE")]
    pub physical_default_value: Option<String>,
    #[serde(rename = "DOP-BASE-REF")]
    pub dop_base_ref: Option<OdxRef>,
    #[serde(rename = "@SEMANTIC")]
    pub semantic: Option<String>,
}

// --- Common types ---

#[derive(Debug, Deserialize)]
pub struct OdxRef {
    #[serde(rename = "@ID-REF")]
    pub id_ref: Option<String>,
    #[serde(rename = "@DOCREF")]
    pub docref: Option<String>,
    #[serde(rename = "@DOCTYPE")]
    pub doctype: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxSnRef {
    #[serde(rename = "@SHORT-NAME")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxText {
    #[serde(rename = "TI")]
    pub ti: Option<String>,
    #[serde(rename = "$text")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminData {
    #[serde(rename = "LANGUAGE")]
    pub language: Option<String>,
    #[serde(rename = "DOC-REVISIONS")]
    pub doc_revisions: Option<DocRevisionsWrapper>,
}

#[derive(Debug, Deserialize)]
pub struct DocRevisionsWrapper {
    #[serde(rename = "DOC-REVISION", default)]
    pub items: Vec<DocRevision>,
}

#[derive(Debug, Deserialize)]
pub struct DocRevision {
    #[serde(rename = "REVISION-LABEL")]
    pub revision_label: Option<String>,
    #[serde(rename = "STATE")]
    pub state: Option<String>,
    #[serde(rename = "DATE")]
    pub date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FunctClass {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
    #[serde(rename = "LONG-NAME")]
    pub long_name: Option<String>,
}

// --- SDGs ---

#[derive(Debug, Deserialize)]
pub struct SdgsWrapper {
    #[serde(rename = "SDG", default)]
    pub items: Vec<OdxSdg>,
}

#[derive(Debug, Deserialize)]
pub struct OdxSdg {
    #[serde(rename = "@GID")]
    pub gid: Option<String>,
    #[serde(rename = "@SI")]
    pub si: Option<String>,
    #[serde(rename = "SDG-CAPTION")]
    pub sdg_caption: Option<OdxSdgCaption>,
    #[serde(rename = "SD", default)]
    pub sds: Vec<OdxSd>,
    #[serde(rename = "SDG", default)]
    pub nested_sdgs: Vec<OdxSdg>,
}

#[derive(Debug, Deserialize)]
pub struct OdxSdgCaption {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "SHORT-NAME")]
    pub short_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OdxSd {
    #[serde(rename = "@SI")]
    pub si: Option<String>,
    #[serde(rename = "$text")]
    pub value: Option<String>,
}
