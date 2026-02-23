//! ODX reference resolution (Phase 2).
//!
//! Builds ID-indexed lookup tables from the parsed ODX tree so that ID-REF
//! and SNREF attributes can be resolved to actual objects.

use std::collections::HashMap;

use crate::odx_model::*;

/// Pre-indexed ODX data for reference resolution.
/// All items are borrowed from the original `Odx` tree.
pub struct OdxIndex<'a> {
    pub requests: HashMap<&'a str, &'a OdxRequest>,
    pub pos_responses: HashMap<&'a str, &'a OdxResponse>,
    pub neg_responses: HashMap<&'a str, &'a OdxResponse>,
    pub global_neg_responses: HashMap<&'a str, &'a OdxResponse>,
    pub data_object_props: HashMap<&'a str, &'a OdxDataObjectProp>,
    pub dtc_dops: HashMap<&'a str, &'a OdxDtcDop>,
    pub structures: HashMap<&'a str, &'a OdxStructure>,
    pub units: HashMap<&'a str, &'a OdxUnit>,
    pub physical_dimensions: HashMap<&'a str, &'a OdxPhysicalDimension>,
    pub tables: HashMap<&'a str, &'a OdxTable>,
    pub layers: HashMap<&'a str, &'a DiagLayerVariant>,
    pub states: HashMap<&'a str, &'a OdxState>,
    pub state_charts: HashMap<&'a str, &'a OdxStateChart>,
    pub diag_services: HashMap<&'a str, &'a OdxDiagService>,
    pub single_ecu_jobs: HashMap<&'a str, &'a OdxSingleEcuJob>,
    pub additional_audiences: HashMap<&'a str, &'a OdxAdditionalAudience>,
    pub funct_classes: HashMap<&'a str, &'a FunctClass>,
}

impl<'a> OdxIndex<'a> {
    /// Build an index from the parsed ODX root.
    pub fn build(odx: &'a Odx) -> Self {
        let mut idx = OdxIndex {
            requests: HashMap::new(),
            pos_responses: HashMap::new(),
            neg_responses: HashMap::new(),
            global_neg_responses: HashMap::new(),
            data_object_props: HashMap::new(),
            dtc_dops: HashMap::new(),
            structures: HashMap::new(),
            units: HashMap::new(),
            physical_dimensions: HashMap::new(),
            tables: HashMap::new(),
            layers: HashMap::new(),
            states: HashMap::new(),
            state_charts: HashMap::new(),
            diag_services: HashMap::new(),
            single_ecu_jobs: HashMap::new(),
            additional_audiences: HashMap::new(),
            funct_classes: HashMap::new(),
        };

        if let Some(dlc) = &odx.diag_layer_container {
            idx.index_layer_list(&dlc.base_variants, |w| &w.items);
            idx.index_layer_list(&dlc.ecu_variants, |w| &w.items);
            idx.index_layer_list(&dlc.ecu_shared_datas, |w| &w.items);
            idx.index_layer_list(&dlc.functional_groups, |w| &w.items);
            idx.index_layer_list(&dlc.protocols, |w| &w.items);
        }

        idx
    }

    fn index_layer_list<W, F>(&mut self, wrapper: &'a Option<W>, get_items: F)
    where
        F: Fn(&'a W) -> &'a [DiagLayerVariant],
    {
        if let Some(w) = wrapper {
            for layer in get_items(w) {
                self.index_layer(layer);
            }
        }
    }

    fn index_layer(&mut self, layer: &'a DiagLayerVariant) {
        if let Some(id) = layer.id.as_deref() {
            self.layers.insert(id, layer);
        }

        if let Some(spec) = &layer.diag_data_dictionary_spec {
            self.index_data_dictionary(spec);
        }

        if let Some(w) = &layer.requests {
            for req in &w.items {
                if let Some(id) = req.id.as_deref() {
                    self.requests.insert(id, req);
                }
            }
        }

        if let Some(w) = &layer.pos_responses {
            for resp in &w.items {
                if let Some(id) = resp.id.as_deref() {
                    self.pos_responses.insert(id, resp);
                }
            }
        }

        if let Some(w) = &layer.neg_responses {
            for resp in &w.items {
                if let Some(id) = resp.id.as_deref() {
                    self.neg_responses.insert(id, resp);
                }
            }
        }

        if let Some(w) = &layer.global_neg_responses {
            for resp in &w.items {
                if let Some(id) = resp.id.as_deref() {
                    self.global_neg_responses.insert(id, resp);
                }
            }
        }

        if let Some(w) = &layer.diag_comms {
            for entry in &w.items {
                match entry {
                    DiagCommEntry::DiagService(ds) => {
                        if let Some(id) = ds.id.as_deref() {
                            self.diag_services.insert(id, ds);
                        }
                    }
                    DiagCommEntry::SingleEcuJob(job) => {
                        if let Some(id) = job.id.as_deref() {
                            self.single_ecu_jobs.insert(id, job);
                        }
                    }
                    DiagCommEntry::DiagCommRef(_) => {}
                }
            }
        }

        if let Some(w) = &layer.state_charts {
            for sc in &w.items {
                if let Some(id) = sc.id.as_deref() {
                    self.state_charts.insert(id, sc);
                }
                if let Some(states) = &sc.states {
                    for s in &states.items {
                        if let Some(id) = s.id.as_deref() {
                            self.states.insert(id, s);
                        }
                    }
                }
            }
        }

        if let Some(w) = &layer.additional_audiences {
            for aa in &w.items {
                if let Some(id) = aa.id.as_deref() {
                    self.additional_audiences.insert(id, aa);
                }
            }
        }

        if let Some(w) = &layer.funct_classs {
            for fc in &w.items {
                if let Some(id) = fc.id.as_deref() {
                    self.funct_classes.insert(id, fc);
                }
            }
        }
    }

    fn index_data_dictionary(&mut self, spec: &'a DiagDataDictionarySpec) {
        if let Some(w) = &spec.data_object_props {
            for dop in &w.items {
                if let Some(id) = dop.id.as_deref() {
                    self.data_object_props.insert(id, dop);
                }
            }
        }

        if let Some(w) = &spec.dtc_dops {
            for dop in &w.items {
                if let Some(id) = dop.id.as_deref() {
                    self.dtc_dops.insert(id, dop);
                }
            }
        }

        if let Some(w) = &spec.structures {
            for s in &w.items {
                if let Some(id) = s.id.as_deref() {
                    self.structures.insert(id, s);
                }
            }
        }

        if let Some(w) = &spec.tables {
            for t in &w.items {
                if let Some(id) = t.id.as_deref() {
                    self.tables.insert(id, t);
                }
            }
        }

        if let Some(unit_spec) = &spec.unit_spec {
            if let Some(w) = &unit_spec.units {
                for u in &w.items {
                    if let Some(id) = u.id.as_deref() {
                        self.units.insert(id, u);
                    }
                }
            }
            if let Some(w) = &unit_spec.physical_dimensions {
                for pd in &w.items {
                    if let Some(id) = pd.id.as_deref() {
                        self.physical_dimensions.insert(id, pd);
                    }
                }
            }
        }
    }
}
