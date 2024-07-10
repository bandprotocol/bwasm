use crate::cache::Cache;
use crate::error::Error;
use crate::imports::create_import_object;
use crate::store::make_store;
use crate::vm::{Environment, Querier};

use std::ptr::NonNull;
use wasmer_middlewares::metering::{get_remaining_points, MeteringPoints};

pub fn run<Q>(
    cache: &mut Cache,
    code: &[u8],
    gas_limit: u64,
    is_prepare: bool,
    querier: Q,
) -> Result<u64, Error>
where
    Q: Querier + 'static,
{
    let owasm_env = Environment::new(querier);
    let mut store = make_store();
    let import_object = create_import_object(&mut store, owasm_env.clone());

    let (instance, _) = cache.get_instance(code, &mut store, &import_object)?;
    let instance_ptr = NonNull::from(&instance);
    owasm_env.set_wasmer_instance(Some(instance_ptr));
    owasm_env.set_gas_left(&mut store, gas_limit);

    // get function and exec
    let entry = if is_prepare { "prepare" } else { "execute" };
    let function = instance
        .exports
        .get_function(entry)
        .unwrap()
        .typed::<(), ()>(&mut store)
        .map_err(|_| Error::BadEntrySignatureError)?;

    function.call(&mut store).map_err(|runtime_err| {
        if let Ok(err) = runtime_err.downcast::<Error>() {
            return err;
        }

        match get_remaining_points(&mut store, &instance) {
            MeteringPoints::Remaining(_) => Error::RuntimeError,
            MeteringPoints::Exhausted => Error::OutOfGasError,
        }
    })?;

    match get_remaining_points(&mut store, &instance) {
        MeteringPoints::Remaining(count) => Ok(gas_limit.saturating_sub(count)),
        MeteringPoints::Exhausted => Err(Error::OutOfGasError),
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::CacheOptions;

    use super::*;
    use crate::compile::compile;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::NamedTempFile;

    pub struct MockQuerier {}

    impl Querier for MockQuerier {
        fn get_span_size(&self) -> i64 {
            300
        }
        fn get_calldata(&self) -> Result<Vec<u8>, Error> {
            Ok(vec![1])
        }
        fn set_return_data(&self, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn get_ask_count(&self) -> i64 {
            10
        }
        fn get_min_count(&self) -> i64 {
            8
        }
        fn get_prepare_time(&self) -> i64 {
            100_000
        }
        fn get_execute_time(&self) -> Result<i64, Error> {
            Ok(100_000)
        }
        fn get_ans_count(&self) -> Result<i64, Error> {
            Ok(8)
        }
        fn ask_external_data(&self, _: i64, _: i64, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn get_external_data_status(&self, _: i64, _: i64) -> Result<i64, Error> {
            Ok(1)
        }
        fn get_external_data(&self, _: i64, _: i64) -> Result<Vec<u8>, Error> {
            Ok(vec![1])
        }
    }

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

    #[test]
    fn test_simple_gas_used() {
        let wasm = wat2wasm(
            r#"(module
            (type (func (param i64 i64 i64 i64) (result)))
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
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
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let querier = MockQuerier {};
        let gas_used = run(&mut cache, &code, u64::MAX, true, querier).unwrap();
        assert_eq!(gas_used, 705019550000 as u64);
    }

    #[test]
    fn test_ask_external_data_gas_used() {
        let wasm = wat2wasm(
            r#"(module
                (type (func (param i64 i64 i64 i64) (result)))
                (import "env" "ask_external_data" (func (type 0)))
                (func
                    (local $idx i32)

                    (i64.const 1)
                    (i64.const 1)
                    (i64.const 1048576)
                    (i64.const 4)
                    call 0

                    (local.set $idx (i32.const 0))
                    (block
                        (loop
                            (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                            (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
                        )
                    )
                )
                (func (;"execute": Resolves with result "beeb";))
                (memory (export "memory") 17)
                (data (i32.const 1048576) "beeb")
                (export "prepare" (func 1))
                (export "execute" (func 2)))
            "#,
        );

        let code = compile(&wasm).unwrap();
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let querier = MockQuerier {};
        let gas_used = run(&mut cache, &code, u64::MAX, true, querier).unwrap();
        assert_eq!(gas_used, 706780650000 as u64);
    }

    #[test]
    #[cfg(not(tarpaulin))]
    fn test_out_of_gas() {
        let wasm = wat2wasm(
            r#"(module
            (type (func (param i64 i64 i64 i64) (result)))
            (func
              (local $idx i32)
              (local.set $idx (i32.const 0))
              (block
                  (loop
                    (local.set $idx (local.get $idx) (i32.const 1) (i32.add) )
                    (br_if 0 (i32.lt_u (local.get $idx) (i32.const 100000)))
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
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let querier = MockQuerier {};
        let out_of_gas_err = run(&mut cache, &code, 10, true, querier).unwrap_err();
        assert_eq!(out_of_gas_err, Error::OutOfGasError);
    }
}
