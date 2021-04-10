// Example code that deserializes and serializes the model.
// extern crate serde;
// #[macro_use]
// extern crate serde_derive;
// extern crate serde_json;
//
// use generated_module::[object Object];
//
// fn main() {
//     let json = r#"{"answer": 42}"#;
//     let model: [object Object] = serde_json::from_str(&json).unwrap();
// }

extern crate serde_derive;
use std::collections::HashMap;

/// OpenContainer Config Specification
#[derive(Serialize, Deserialize)]
pub struct ImageSpec {
    #[serde(rename = "architecture")]
    pub architecture: String,

    #[serde(rename = "author")]
    pub author: Option<String>,

    #[serde(rename = "config")]
    pub config: Option<Config>,

    #[serde(rename = "created")]
    pub created: Option<String>,

    #[serde(rename = "history")]
    pub history: Option<Vec<History>>,

    #[serde(rename = "os")]
    pub os: String,

    #[serde(rename = "rootfs")]
    pub rootfs: Rootfs,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "Cmd")]
    pub cmd: Option<Vec<String>>,

    #[serde(rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,

    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,

    #[serde(rename = "ExposedPorts")]
    pub exposed_ports: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "Labels")]
    pub labels: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "StopSignal")]
    pub stop_signal: Option<String>,

    #[serde(rename = "User")]
    pub user: Option<String>,

    #[serde(rename = "Volumes")]
    pub volumes: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "WorkingDir")]
    pub working_dir: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct History {
    #[serde(rename = "author")]
    pub author: Option<String>,

    #[serde(rename = "comment")]
    pub comment: Option<String>,

    #[serde(rename = "created")]
    pub created: Option<String>,

    #[serde(rename = "created_by")]
    pub created_by: Option<String>,

    #[serde(rename = "empty_layer")]
    pub empty_layer: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Rootfs {
    #[serde(rename = "diff_ids")]
    pub diff_ids: Vec<String>,

    #[serde(rename = "type")]
    pub rootfs_type: Type,
}

#[derive(Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "layers")]
    Layers,
}
