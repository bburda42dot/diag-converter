//! ODX inheritance merge (Phase 3).
//!
//! Merges parent layer content into child layers, respecting NOT-INHERITED
//! exclusion lists. The ODX hierarchy is: Protocol -> FunctionalGroup ->
//! BaseVariant -> EcuVariant, where each child inherits and can override
//! services/DOPs from its parent.

use std::collections::HashSet;

use crate::odx_model::*;
use crate::ref_resolver::OdxIndex;

/// A resolved DiagLayer with content merged from parents.
/// Contains the layer's own items plus inherited items (minus NOT-INHERITED).
pub struct MergedLayer<'a> {
    pub layer: &'a DiagLayerVariant,
    pub diag_services: Vec<&'a OdxDiagService>,
    pub single_ecu_jobs: Vec<&'a OdxSingleEcuJob>,
    pub requests: Vec<&'a OdxRequest>,
    pub pos_responses: Vec<&'a OdxResponse>,
    pub neg_responses: Vec<&'a OdxResponse>,
    pub global_neg_responses: Vec<&'a OdxResponse>,
    pub data_object_props: Vec<&'a OdxDataObjectProp>,
    pub dtc_dops: Vec<&'a OdxDtcDop>,
    pub structures: Vec<&'a OdxStructure>,
}

impl<'a> MergedLayer<'a> {
    /// Create an empty MergedLayer with no inherited or own content.
    fn empty(layer: &'a DiagLayerVariant) -> Self {
        Self {
            layer,
            diag_services: Vec::new(),
            single_ecu_jobs: Vec::new(),
            requests: Vec::new(),
            pos_responses: Vec::new(),
            neg_responses: Vec::new(),
            global_neg_responses: Vec::new(),
            data_object_props: Vec::new(),
            dtc_dops: Vec::new(),
            structures: Vec::new(),
        }
    }

    /// Merge a layer with content inherited from its parents.
    pub fn merge(layer: &'a DiagLayerVariant, index: &'a OdxIndex<'a>) -> Self {
        let mut visited = HashSet::new();
        Self::merge_inner(layer, index, &mut visited)
    }

    fn merge_inner(
        layer: &'a DiagLayerVariant,
        index: &'a OdxIndex<'a>,
        visited: &mut HashSet<String>,
    ) -> Self {
        // Cycle detection: use the layer's @ID attribute for identity (same key as
        // index.layers). Fall back to short_name if no ID is present.
        let layer_id = layer
            .id
            .as_deref()
            .or(layer.short_name.as_deref())
            .unwrap_or("")
            .to_string();
        if !visited.insert(layer_id.clone()) {
            log::warn!(
                "Circular parent reference detected at layer '{}', stopping inheritance",
                layer_id
            );
            let mut merged = Self::empty(layer);
            merged.add_own_content(layer);
            return merged;
        }

        let mut merged = Self::empty(layer);

        // Collect NOT-INHERITED short names from all parent refs
        let mut excluded_diag_comms = HashSet::new();
        let mut excluded_dops = HashSet::new();
        let mut excluded_global_neg = HashSet::new();

        if let Some(parent_refs) = &layer.parent_refs {
            for pref in &parent_refs.items {
                // Collect exclusions
                if let Some(w) = &pref.not_inherited_diag_comms {
                    for ni in &w.items {
                        if let Some(snref) = &ni.snref {
                            if let Some(sn) = &snref.short_name {
                                excluded_diag_comms.insert(sn.as_str());
                            }
                        }
                    }
                }
                if let Some(w) = &pref.not_inherited_dops {
                    for ni in &w.items {
                        if let Some(snref) = &ni.snref {
                            if let Some(sn) = &snref.short_name {
                                excluded_dops.insert(sn.as_str());
                            }
                        }
                    }
                }
                if let Some(w) = &pref.not_inherited_global_neg_responses {
                    for ni in &w.items {
                        if let Some(snref) = &ni.snref {
                            if let Some(sn) = &snref.short_name {
                                excluded_global_neg.insert(sn.as_str());
                            }
                        }
                    }
                }

                // Resolve parent layer and inherit its content
                if let Some(parent_id) = &pref.id_ref {
                    if let Some(parent_layer) = index.layers.get(parent_id.as_str()) {
                        let parent_merged =
                            MergedLayer::merge_inner(parent_layer, index, visited);
                        merged.inherit_from(
                            &parent_merged,
                            &excluded_diag_comms,
                            &excluded_dops,
                            &excluded_global_neg,
                        );
                    }
                }
            }
        }

        // Add own content (overrides inherited by short_name)
        merged.add_own_content(layer);

        merged
    }

    fn inherit_from(
        &mut self,
        parent: &MergedLayer<'a>,
        excluded_diag_comms: &HashSet<&str>,
        excluded_dops: &HashSet<&str>,
        excluded_global_neg: &HashSet<&str>,
    ) {
        // Inherit diag services (filtered by NOT-INHERITED)
        for ds in &parent.diag_services {
            if let Some(sn) = &ds.short_name {
                if !excluded_diag_comms.contains(sn.as_str()) {
                    self.diag_services.push(ds);
                }
            }
        }

        // Inherit ECU jobs (filtered by NOT-INHERITED diag-comms)
        for job in &parent.single_ecu_jobs {
            if let Some(sn) = &job.short_name {
                if !excluded_diag_comms.contains(sn.as_str()) {
                    self.single_ecu_jobs.push(job);
                }
            }
        }

        // Inherit requests/responses
        for r in &parent.requests {
            self.requests.push(r);
        }
        for r in &parent.pos_responses {
            self.pos_responses.push(r);
        }
        for r in &parent.neg_responses {
            self.neg_responses.push(r);
        }
        for r in &parent.global_neg_responses {
            if let Some(sn) = &r.short_name {
                if !excluded_global_neg.contains(sn.as_str()) {
                    self.global_neg_responses.push(r);
                }
            }
        }

        // Inherit DOPs (filtered by NOT-INHERITED)
        for dop in &parent.data_object_props {
            if let Some(sn) = &dop.short_name {
                if !excluded_dops.contains(sn.as_str()) {
                    self.data_object_props.push(dop);
                }
            }
        }

        for dop in &parent.dtc_dops {
            self.dtc_dops.push(dop);
        }

        for s in &parent.structures {
            self.structures.push(s);
        }
    }

    fn add_own_content(&mut self, layer: &'a DiagLayerVariant) {
        // Collect own short names for dedup against inherited content
        let mut own_service_names: HashSet<&str> = HashSet::new();
        let mut own_job_names: HashSet<&str> = HashSet::new();

        if let Some(w) = &layer.diag_comms {
            for entry in &w.items {
                match entry {
                    DiagCommEntry::DiagService(ds) => {
                        if let Some(sn) = &ds.short_name {
                            own_service_names.insert(sn.as_str());
                        }
                    }
                    DiagCommEntry::SingleEcuJob(job) => {
                        if let Some(sn) = &job.short_name {
                            own_job_names.insert(sn.as_str());
                        }
                    }
                    DiagCommEntry::DiagCommRef(_) => {}
                }
            }
        }

        // Remove inherited items overridden by own content
        self.diag_services.retain(|ds| {
            ds.short_name
                .as_deref()
                .map_or(true, |sn| !own_service_names.contains(sn))
        });
        self.single_ecu_jobs.retain(|j| {
            j.short_name
                .as_deref()
                .map_or(true, |sn| !own_job_names.contains(sn))
        });

        // Add own items (once)
        if let Some(w) = &layer.diag_comms {
            for entry in &w.items {
                match entry {
                    DiagCommEntry::DiagService(ds) => {
                        self.diag_services.push(ds);
                    }
                    DiagCommEntry::SingleEcuJob(job) => {
                        self.single_ecu_jobs.push(job);
                    }
                    DiagCommEntry::DiagCommRef(_) => {}
                }
            }
        }

        // Own requests/responses
        if let Some(w) = &layer.requests {
            for r in &w.items {
                self.requests.push(r);
            }
        }
        if let Some(w) = &layer.pos_responses {
            for r in &w.items {
                self.pos_responses.push(r);
            }
        }
        if let Some(w) = &layer.neg_responses {
            for r in &w.items {
                self.neg_responses.push(r);
            }
        }
        if let Some(w) = &layer.global_neg_responses {
            for r in &w.items {
                self.global_neg_responses.push(r);
            }
        }

        // Own DOPs
        if let Some(spec) = &layer.diag_data_dictionary_spec {
            if let Some(w) = &spec.data_object_props {
                for dop in &w.items {
                    self.data_object_props.push(dop);
                }
            }
            if let Some(w) = &spec.dtc_dops {
                for dop in &w.items {
                    self.dtc_dops.push(dop);
                }
            }
            if let Some(w) = &spec.structures {
                for s in &w.items {
                    self.structures.push(s);
                }
            }
        }
    }
}
