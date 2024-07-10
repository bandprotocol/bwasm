use crate::Error;

use wasm_instrument::parity_wasm::{
    builder,
    elements::{deserialize_buffer, serialize, External, MemoryType, Module},
};
use wasmer::wasmparser;

// inspired by https://github.com/CosmWasm/cosmwasm/issues/81
// 512 pages = 32mb
static MEMORY_LIMIT: u32 = 512; // in pages
static MAX_STACK_HEIGHT: u32 = 16 * 1024; // 16Kib of stack.

static REQUIRED_EXPORTS: &[&str] = &["prepare", "execute"];
static SUPPORTED_IMPORTS: &[&str] = &[
    "env.get_span_size",
    "env.read_calldata",
    "env.set_return_data",
    "env.get_ask_count",
    "env.get_min_count",
    "env.get_prepare_time",
    "env.get_execute_time",
    "env.get_ans_count",
    "env.ask_external_data",
    "env.get_external_data_status",
    "env.read_external_data",
    "env.ecvrf_verify",
];

pub fn compile(code: &[u8]) -> Result<Vec<u8>, Error> {
    // Check that the given Wasm code is indeed a valid Wasm.
    wasmparser::validate(code).map_err(|_| Error::ValidationError)?;

    // Start the compiling chains.
    let module = deserialize_buffer(code).map_err(|_| Error::DeserializationError)?;
    check_wasm_exports(&module)?;
    check_wasm_imports(&module)?;
    let module = inject_memory(module)?;
    let module = inject_stack_height(module)?;

    // Serialize the final Wasm code back to bytes.
    serialize(module).map_err(|_| Error::SerializationError)
}

fn check_wasm_exports(module: &Module) -> Result<(), Error> {
    let available_exports: Vec<&str> = module.export_section().map_or(vec![], |export_section| {
        export_section.entries().iter().map(|entry| entry.field()).collect()
    });

    for required_export in REQUIRED_EXPORTS {
        if !available_exports.contains(required_export) {
            return Err(Error::InvalidExportsError);
        }
    }

    Ok(())
}

fn check_wasm_imports(module: &Module) -> Result<(), Error> {
    let required_imports =
        module.import_section().map_or(vec![], |import_section| import_section.entries().to_vec());

    for required_import in required_imports {
        let full_name = format!("{}.{}", required_import.module(), required_import.field());
        if !SUPPORTED_IMPORTS.contains(&full_name.as_str()) {
            return Err(Error::InvalidImportsError);
        }

        match required_import.external() {
            External::Function(_) => (), // ok
            _ => return Err(Error::InvalidImportsError),
        };
    }

    Ok(())
}

fn inject_memory(module: Module) -> Result<Module, Error> {
    let mut m = module;
    let section = match m.memory_section() {
        Some(section) => section,
        None => return Err(Error::BadMemorySectionError),
    };

    // The valid wasm has only the section length of memory.
    // We check the wasm is valid in the first step of compile fn.
    let memory = section.entries()[0];
    let limits = memory.limits();

    if limits.initial() > MEMORY_LIMIT {
        return Err(Error::BadMemorySectionError);
    }

    if limits.maximum() != None {
        return Err(Error::BadMemorySectionError);
    }

    // set max memory page = MEMORY_LIMIT
    let memory = MemoryType::new(limits.initial(), Some(MEMORY_LIMIT));

    // Memory existance already checked
    let entries = m.memory_section_mut().unwrap().entries_mut();
    entries.pop();
    entries.push(memory);

    Ok(builder::from_module(m).build())
}

fn inject_stack_height(module: Module) -> Result<Module, Error> {
    wasm_instrument::inject_stack_limiter(module, MAX_STACK_HEIGHT)
        .map_err(|_| Error::StackHeightInjectionError)
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::NamedTempFile;

    fn wat2wasm(wat: impl AsRef<[u8]>) -> Vec<u8> {
        let mut input_file = NamedTempFile::new().unwrap();
        let mut output_file = NamedTempFile::new().unwrap();
        input_file.write_all(wat.as_ref()).unwrap();
        Command::new("wat2wasm")
            .args(&[
                input_file.path().to_str().unwrap(),
                "-o",
                output_file.path().to_str().unwrap(),
            ])
            .output()
            .unwrap();
        let mut wasm = Vec::new();
        output_file.read_to_end(&mut wasm).unwrap();
        wasm
    }

    fn get_module_from_wasm(code: &[u8]) -> Module {
        match deserialize_buffer(code) {
            Ok(deserialized) => deserialized,
            Err(_) => panic!("Cannot deserialized"),
        }
    }

    #[test]
    fn test_inject_memory_ok() {
        let wasm = wat2wasm(r#"(module (memory 1))"#);
        let module = get_module_from_wasm(&wasm);
        assert_matches!(inject_memory(module), Ok(_));
    }

    #[test]
    fn test_inject_memory_no_memory() {
        let wasm = wat2wasm("(module)");
        let module = get_module_from_wasm(&wasm);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }

    #[test]
    fn test_inject_memory_two_memories() {
        // Generated manually because wat2wasm protects us from creating such Wasm:
        // "error: only one memory block allowed"
        let wasm = hex::decode(concat!(
            "0061736d", // magic bytes
            "01000000", // binary version (uint32)
            "05",       // section type (memory)
            "07",       // section length
            "02",       // number of memories
            "0009",     // element of type "resizable_limits", min=9, max=unset
            "0009",     // element of type "resizable_limits", min=9, max=unset
        ))
        .unwrap();
        let r = compile(&wasm);
        assert_eq!(r, Err(Error::ValidationError));
    }

    #[test]
    fn test_inject_memory_initial_size() {
        let wasm_ok = wat2wasm("(module (memory 512))");
        let module = get_module_from_wasm(&wasm_ok);
        assert_matches!(inject_memory(module), Ok(_));
        let wasm_too_big = wat2wasm("(module (memory 513))");
        let module = get_module_from_wasm(&wasm_too_big);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }

    #[test]
    fn test_inject_memory_maximum_size() {
        let wasm = wat2wasm("(module (memory 1 5))");
        let module = get_module_from_wasm(&wasm);
        assert_eq!(inject_memory(module), Err(Error::BadMemorySectionError));
    }

    #[test]
    fn test_inject_stack_height() {
        let wasm = wat2wasm(
            r#"(module
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 1000000000)))
                  )
                )
            )
            (func (;"execute": Resolves with result "beeb";)
            )
            (memory 17)
            (data (i32.const 1048576) "beeb") (;str = "beeb";)
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let module = inject_stack_height(get_module_from_wasm(&wasm)).unwrap();
        let wasm = serialize(module).unwrap();
        let expected = wat2wasm(
            r#"(module
                (type (;0;) (func))
                (func (;0;) (type 0)
                  (local i32)
                  i32.const 0
                  local.set 0
                  block  ;; label = @1
                    loop  ;; label = @2
                      local.get 0
                      i32.const 1
                      i32.add
                      local.set 0
                      local.get 0
                      i32.const 1000000000
                      i32.lt_u
                      br_if 0 (;@2;)
                    end
                  end)
                (func (;1;) (type 0))
                (func (;2;) (type 0)
                  global.get 0
                  i32.const 5
                  i32.add
                  global.set 0
                  global.get 0
                  i32.const 16384
                  i32.gt_u
                  if  ;; label = @1
                    unreachable
                  end
                  call 0
                  global.get 0
                  i32.const 5
                  i32.sub
                  global.set 0)
                (func (;3;) (type 0)
                  global.get 0
                  i32.const 2
                  i32.add
                  global.set 0
                  global.get 0
                  i32.const 16384
                  i32.gt_u
                  if  ;; label = @1
                    unreachable
                  end
                  call 1
                  global.get 0
                  i32.const 2
                  i32.sub
                  global.set 0)
                (memory (;0;) 17)
                (global (;0;) (mut i32) (i32.const 0))
                (export "prepare" (func 2))
                (export "execute" (func 3))
                (data (;0;) (i32.const 1048576) "beeb"))"#,
        );
        assert_eq!(wasm, expected);
    }

    #[test]
    fn test_check_wasm_imports() {
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i64 i64) (result i64)))
                (import "env" "beeb" (func (type 0))))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_imports(&module), Err(Error::InvalidImportsError));
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i64 i64) (result i64)))
                (import "env" "ask_external_data" (func  (type 0))))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_imports(&module), Ok(()));
    }

    #[test]
    fn test_check_wasm_exports() {
        let wasm = wat2wasm(
            r#"(module
            (func $execute (export "execute")))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_exports(&module), Err(Error::InvalidExportsError));
        let wasm = wat2wasm(
            r#"(module
                (func $prepare (export "prepare")))"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_exports(&module), Err(Error::InvalidExportsError));
        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );
        let module = get_module_from_wasm(&wasm);
        assert_eq!(check_wasm_exports(&module), Ok(()));
    }

    #[test]
    fn test_compile() {
        let wasm = wat2wasm(
            r#"(module
            (type (func (param i64 i64 i64 i64) (result i64)))
            (import "env" "ask_external_data" (func (type 0)))
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 1000000000)))
                  )
                )
            )
            (func (;"execute": Resolves with result "beeb";)
            )
            (memory 17)
            (data (i32.const 1048576) "beeb") (;str = "beeb";)
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let code = compile(&wasm).unwrap();
        let expected = wat2wasm(
            r#"(module
                (type (;0;) (func (param i64 i64 i64 i64) (result i64)))
                (type (;1;) (func))
                (import "env" "ask_external_data" (func (;0;) (type 0)))
                (func (;1;) (type 1)
                  (local i32)
                  i32.const 0
                  local.set 0
                  block  ;; label = @1
                    loop  ;; label = @2
                      local.get 0
                      i32.const 1
                      i32.add
                      local.set 0
                      local.get 0
                      i32.const 1000000000
                      i32.lt_u
                      br_if 0 (;@2;)
                    end
                  end)
                (func (;2;) (type 1))
                (func (;3;) (type 1)
                  global.get 0
                  i32.const 5
                  i32.add
                  global.set 0
                  global.get 0
                  i32.const 16384
                  i32.gt_u
                  if  ;; label = @1
                    unreachable
                  end
                  call 1
                  global.get 0
                  i32.const 5
                  i32.sub
                  global.set 0)
                (memory (;0;) 17 512)
                (global (;0;) (mut i32) (i32.const 0))
                (export "prepare" (func 0))
                (export "execute" (func 3))
                (data (;0;) (i32.const 1048576) "beeb"))"#,
        );
        assert_eq!(code, expected);
    }
}
