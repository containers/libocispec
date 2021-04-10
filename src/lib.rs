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

#[cfg(test)]
mod tests {
  use crate::runtime;
  #[test]
  fn test_runtime_load(){
    match runtime::Spec::load("src/runtime/test/config.test.json") {
        Ok(_) => {},
        Err(e) => panic!("{}", e),
    }
  }

  #[test]
  fn test_runtime_assert_spec(){
    match runtime::Spec::load("src/runtime/test/config.test.json") {
        Ok(spec) => {assert_eq!(spec.oci_version, "0.5.0-dev")},
        Err(e) => panic!("{}", e),
    }
  }
}
