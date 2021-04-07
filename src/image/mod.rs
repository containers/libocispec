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
    architecture: String,

    #[serde(rename = "author")]
    author: Option<String>,

    #[serde(rename = "config")]
    config: Option<Config>,

    #[serde(rename = "created")]
    created: Option<String>,

    #[serde(rename = "history")]
    history: Option<Vec<History>>,

    #[serde(rename = "os")]
    os: String,

    #[serde(rename = "rootfs")]
    rootfs: Rootfs,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "Cmd")]
    cmd: Option<Vec<String>>,

    #[serde(rename = "Entrypoint")]
    entrypoint: Option<Vec<String>>,

    #[serde(rename = "Env")]
    env: Option<Vec<String>>,

    #[serde(rename = "ExposedPorts")]
    exposed_ports: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "StopSignal")]
    stop_signal: Option<String>,

    #[serde(rename = "User")]
    user: Option<String>,

    #[serde(rename = "Volumes")]
    volumes: Option<HashMap<String, Option<serde_json::Value>>>,

    #[serde(rename = "WorkingDir")]
    working_dir: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct History {
    #[serde(rename = "author")]
    author: Option<String>,

    #[serde(rename = "comment")]
    comment: Option<String>,

    #[serde(rename = "created")]
    created: Option<String>,

    #[serde(rename = "created_by")]
    created_by: Option<String>,

    #[serde(rename = "empty_layer")]
    empty_layer: Option<bool>,
}

#[derive(Serialize, Deserialize)]
pub struct Rootfs {
    #[serde(rename = "diff_ids")]
    diff_ids: Vec<String>,

    #[serde(rename = "type")]
    rootfs_type: Type,
}

#[derive(Serialize, Deserialize)]
pub enum Type {
    #[serde(rename = "layers")]
    Layers,
}
