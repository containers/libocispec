const {
  quicktype,
  InputData,
  jsonInputForTargetLanguage,
  JSONSchemaInput,
  JSONSchemaStore,
} = require("quicktype-core");
const $RefParser = require("@apidevtools/json-schema-ref-parser");

const BREAKLINE = "\n";
const SCHEMA_ENTRYPOINT = "config-schema.json";
const BASE_STRUCT_RUNTIME_SPEC = "Spec";
const BASE_STRUCT_IMAGE_SPEC = "ImageSpec";

var fs = require('fs');

function writeFile(fileName, data){
  fs.writeFile(fileName, data, function (err) {
    if (err) throw err;
      console.log('Successfully generated '+fileName);
  });
}

async function quicktypeJSONSchema(targetLanguage, typeName, jsonSchemaString) {
  const schemaInput = new JSONSchemaInput(new JSONSchemaStore());

  await schemaInput.addSource({ name: typeName, schema: jsonSchemaString });
  const inputData = new InputData();
  inputData.addInput(schemaInput);
  return await quicktype({
    inputData,
    lang: targetLanguage,
  });
}

function dereference(parentStructName, mySchema, fileName){
  $RefParser.dereference(mySchema, (err, schema) => {
    if (err) {
      console.error(err);
    }
    else {
      schemaGen = JSON.stringify(schema);
      generateSchema(parentStructName, JSON.stringify(schema), fileName);
    }
  })
}

async function generateSchema(parentStructName ,schema, fileName) {
   const { lines: rustSpec } = await quicktypeJSONSchema(
    "rust",
    parentStructName, 
    schema
  );
  writeFile(fileName, rustSpec.join(BREAKLINE));
}

function generator(parentStructName ,base, entryPoint, outputPath){
  var rootPath = process.cwd();
  process.chdir(base);
  const myschema = require(base+"/"+entryPoint);
  dereference(parentStructName ,myschema, rootPath+"/"+outputPath);
  process.chdir(rootPath);
}

generator(BASE_STRUCT_RUNTIME_SPEC,'./runtime-spec/schema', SCHEMA_ENTRYPOINT, 'src/runtime/mod.rs');
generator(BASE_STRUCT_IMAGE_SPEC,'./image-spec/schema', SCHEMA_ENTRYPOINT, 'src/image/mod.rs');
