#[macro_use]

extern crate serde;
extern crate serde_derive;
extern crate serde_json;
pub mod serialize;
pub mod image;
pub mod runtime;

impl runtime::Spec {
    pub fn load(path: &str) -> Result<runtime::Spec, serialize::SerializeError> {
        serialize::deserialize(path)    
    }
    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)    
    }
}

impl image::ImageSpec {
    pub fn load(path: &str) -> Result<image::ImageSpec, serialize::SerializeError> {
        serialize::deserialize(path)    
    }
    pub fn save(&self, path: &str) -> Result<(), serialize::SerializeError> {
        serialize::serialize(self, path)    
    }
}
