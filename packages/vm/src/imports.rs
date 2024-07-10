use crate::error::Error;
use crate::vm::{Environment, Querier};

use wasmer::{imports, Function, Imports, FunctionEnv, AsStoreMut, FunctionEnvMut};

use owasm_crypto::ecvrf;
use owasm_crypto::error::CryptoError;

const IMPORTED_FUNCTION_GAS: u64 = 750_000_000;
const ECVRF_VERIFY_GAS: u64 = 7_500_000_000_000;

fn require_mem_range(max_range: usize, require_range: usize) -> Result<(), Error> {
    if max_range < require_range {
        return Err(Error::MemoryOutOfBoundError);
    }
    Ok(())
}

fn safe_convert<M, N>(a: M) -> Result<N, Error>
where
    M: TryInto<N>,
{
    a.try_into().map_err(|_| Error::ConvertTypeOutOfBound)
}

fn safe_add(a: i64, b: i64) -> Result<usize, Error> {
    (safe_convert::<_, usize>(a)?).checked_add(safe_convert(b)?).ok_or(Error::MemoryOutOfBoundError)
}

fn read_memory<Q>(env: &Environment<Q>, store: &mut impl AsStoreMut, ptr: i64, len: i64) -> Result<Vec<u8>, Error>
where
    Q: Querier + 'static,
{
    if ptr < 0 {
        return Err(Error::MemoryOutOfBoundError);
    }
    let memory = env.memory()?;
    let view = memory.view(store);
    require_mem_range(view.size().bytes().0, safe_add(ptr, len)?)?;

    let mut result = vec![0u8; len as usize];

    view.read(safe_convert(ptr)?, &mut result).map_err(|_err| Error::MemoryOutOfBoundError)?;

    Ok(result)
}

fn write_memory<Q>(env: &Environment<Q>, store: &mut impl AsStoreMut, ptr: i64, data: Vec<u8>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    if ptr < 0 {
        return Err(Error::MemoryOutOfBoundError);
    }
    let memory = env.memory()?;
    let view = memory.view(store);
    require_mem_range(view.size().bytes().0, safe_add(ptr, safe_convert(data.len())?)?)?;

    view.write(safe_convert(ptr)?, &data).map_err(|_err| Error::MemoryOutOfBoundError)?;

    Ok(safe_convert(data.len())?)
}

fn calculate_read_memory_gas(len: i64) -> u64 {
    1_000_000_000_u64.saturating_add((len as u64).saturating_mul(1_500_000))
}

fn calculate_write_memory_gas(len: usize) -> u64 {
    2_250_000_000_u64.saturating_add((len as u64).saturating_mul(30_000_000))
}

fn do_gas<Q>(mut env: FunctionEnvMut<Environment<Q>>, _gas: u32) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    Ok(())
}

fn do_get_span_size<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    Ok(data.with_querier_from_context(|querier| querier.get_span_size()))
}

fn do_read_calldata<Q>(mut env: FunctionEnvMut<Environment<Q>>, ptr: i64) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();
        let calldata = querier.get_calldata()?;

        if safe_convert::<_, i64>(calldata.len())? > span_size {
            return Err(Error::SpanTooSmallError);
        }

        data.decrease_gas_left(
            &mut store,
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(calldata.len())),
        )?;
        write_memory(data, &mut store, ptr, calldata)
    })
}

fn do_set_return_data<Q>(mut env: FunctionEnvMut<Environment<Q>>, ptr: i64, len: i64) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    if len < 0 {
        return Err(Error::DataLengthOutOfBound);
    }
    data.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();

        if len > span_size {
            return Err(Error::SpanTooSmallError);
        }
        data.decrease_gas_left(
            &mut store,
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(len)),
        )?;

        let data: Vec<u8> = read_memory(data, &mut store, ptr, len)?;
        querier.set_return_data(&data)
    })
}

fn do_get_ask_count<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    Ok(data.with_querier_from_context(|querier| querier.get_ask_count()))
}

fn do_get_min_count<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    Ok(data.with_querier_from_context(|querier| querier.get_min_count()))
}

fn do_get_prepare_time<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    Ok(data.with_querier_from_context(|querier| querier.get_prepare_time()))
}

fn do_get_execute_time<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    data.with_querier_from_context(|querier| querier.get_execute_time())
}

fn do_get_ans_count<Q>(mut env: FunctionEnvMut<Environment<Q>>) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    data.with_querier_from_context(|querier| querier.get_ans_count())
}

fn do_ask_external_data<Q>(
    mut env: FunctionEnvMut<Environment<Q>>,
    eid: i64,
    did: i64,
    ptr: i64,
    len: i64,
) -> Result<(), Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    if len < 0 {
        return Err(Error::DataLengthOutOfBound);
    }
    data.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();

        if len > span_size {
            return Err(Error::SpanTooSmallError);
        }
        data.decrease_gas_left(
            &mut store,
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(len)),
        )?;

        let return_data: Vec<u8> = read_memory(data, &mut store, ptr, len)?;
        querier.ask_external_data(eid, did, &return_data)
    })
}

fn do_get_external_data_status<Q>(mut env: FunctionEnvMut<Environment<Q>>, eid: i64, vid: i64) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.decrease_gas_left(&mut store, IMPORTED_FUNCTION_GAS)?;
    data.with_querier_from_context(|querier| querier.get_external_data_status(eid, vid))
}

fn do_read_external_data<Q>(
    mut env: FunctionEnvMut<Environment<Q>>,
    eid: i64,
    vid: i64,
    ptr: i64,
) -> Result<i64, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    data.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();
        let external_data = querier.get_external_data(eid, vid)?;

        if safe_convert::<_, i64>(external_data.len())? > span_size {
            return Err(Error::SpanTooSmallError);
        }

        data.decrease_gas_left(
            &mut store,
            IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(external_data.len())),
        )?;
        write_memory(data, &mut store, ptr, external_data)
    })
}

fn do_ecvrf_verify<Q>(
    mut env: FunctionEnvMut<Environment<Q>>,
    y_ptr: i64,
    y_len: i64,
    pi_ptr: i64,
    pi_len: i64,
    alpha_ptr: i64,
    alpha_len: i64,
) -> Result<u32, Error>
where
    Q: Querier + 'static,
{
    let (data, mut store) = env.data_and_store_mut();

    if y_len < 0 || pi_len < 0 || alpha_len < 0 {
        return Err(Error::DataLengthOutOfBound);
    }
    data.with_querier_from_context(|querier| {
        let span_size = querier.get_span_size();

        if y_len > span_size || pi_len > span_size || alpha_len > span_size {
            return Err(Error::SpanTooSmallError);
        }
        // consume gas relatively to the function running time (~7.5ms)
        data.decrease_gas_left(&mut store, ECVRF_VERIFY_GAS)?;
        let y: Vec<u8> = read_memory(data, &mut store, y_ptr, y_len)?;
        let pi: Vec<u8> = read_memory(data, &mut store, pi_ptr, pi_len)?;
        let alpha: Vec<u8> = read_memory(data, &mut store, alpha_ptr, alpha_len)?;

        let result = ecvrf::ecvrf_verify(&y, &pi, &alpha);
        Ok(result.map_or_else(
            |err| match err {
                CryptoError::InvalidPointOnCurve { .. }
                | CryptoError::InvalidPubkeyFormat { .. }
                | CryptoError::InvalidProofFormat { .. }
                | CryptoError::InvalidHashFormat { .. }
                | CryptoError::GenericErr { .. } => err.code(),
            },
            |valid| if valid { 0 } else { 1 },
        ))
    })
}

pub fn create_import_object<Q>(store: &mut impl AsStoreMut, owasm_env: Environment<Q>) -> Imports
where
    Q: Querier + 'static,
{
    let env = FunctionEnv::new(store, owasm_env);

    imports! {
        "env" => {
            "gas" => Function::new_typed_with_env(store, &env, do_gas),
            "get_span_size" => Function::new_typed_with_env(store, &env, do_get_span_size),
            "read_calldata" => Function::new_typed_with_env(store, &env, do_read_calldata),
            "set_return_data" => Function::new_typed_with_env(store, &env, do_set_return_data),
            "get_ask_count" => Function::new_typed_with_env(store, &env, do_get_ask_count),
            "get_min_count" => Function::new_typed_with_env(store, &env, do_get_min_count),
            "get_prepare_time" => Function::new_typed_with_env(store, &env, do_get_prepare_time),
            "get_execute_time" => Function::new_typed_with_env(store, &env, do_get_execute_time),
            "get_ans_count" => Function::new_typed_with_env(store, &env, do_get_ans_count),
            "ask_external_data" => Function::new_typed_with_env(store, &env, do_ask_external_data),
            "get_external_data_status" => Function::new_typed_with_env(store, &env, do_get_external_data_status),
            "read_external_data" => Function::new_typed_with_env(store, &env, do_read_external_data),
            "ecvrf_verify" => Function::new_typed_with_env(store, &env, do_ecvrf_verify),
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::cache::{Cache, CacheOptions};
    use crate::compile::compile;
    use crate::store::make_store;

    use std::io::{Read, Write};
    use std::process::Command;
    use std::ptr::NonNull;
    use tempfile::NamedTempFile;
    use wasmer::ExternType::Function;
    use wasmer::{FunctionType, Store};
    use wasmer::Instance;
    use wasmer_types::Type::{I32, I64};

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

    fn create_owasm_env() -> (Environment<MockQuerier>, Instance, Store) {
        let wasm = wat2wasm(
            r#"(module
            (func
            )
            (func
              )
              (memory (export "memory") 100)
              (data (i32.const 1048576) "beeb") 
            (export "prepare" (func 0))
            (export "execute" (func 1)))
          "#,
        );
        let code = compile(&wasm).unwrap();

        let querier = MockQuerier {};
        let owasm_env = Environment::new(querier);
        let mut store = make_store();
        let import_object = create_import_object(&mut store, owasm_env.clone());
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let (instance, _) = cache.get_instance(&code, &mut store, &import_object).unwrap();



        return (owasm_env, instance, store);
    }

    #[test]
    fn test_wrapper_fn() {
        let querier = MockQuerier {};
        let owasm_env = Environment::new(querier);
        let mut store = make_store();
        assert_eq!(Ok(()), require_mem_range(2, 1));
        assert_eq!(Err(Error::MemoryOutOfBoundError), require_mem_range(1, 2));
        assert_eq!(Ok(()), require_mem_range(usize::MAX, usize::MAX));
        assert_eq!(Ok(usize::MAX), safe_convert(usize::MAX as u64));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_convert::<_, usize>(-1));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_convert::<_, usize>(i64::MIN));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_convert::<_, i64>(usize::MAX));
        assert_eq!(Ok(10), safe_add(4, 6));
        assert_eq!(Ok(i64::MAX as usize + 1), safe_add(i64::MAX, 1));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_add(-1, 6));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_add(5, -10));
        assert_eq!(Err(Error::ConvertTypeOutOfBound), safe_add(usize::MAX as i64, 1));
        assert_eq!(Err(Error::MemoryOutOfBoundError), read_memory(&owasm_env, &mut store, -1, 1));
        assert_eq!(Err(Error::MemoryOutOfBoundError), write_memory(&owasm_env, &mut store, -1, vec! {}))
    }

    #[test]
    fn test_import_object_function_type() {
        let querier = MockQuerier {};
        let owasm_env = Environment::new(querier);
        let mut store = make_store();
        assert_eq!(create_import_object(&mut store, owasm_env.clone()).iter().count(), 13);

        //assert_eq!(create_import_object(&store, owasm_env.clone()).externs_vec()[0].1, "gas");
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "gas").unwrap().ty(&mut store),
            Function(FunctionType::new([I32], []))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[1].1,
        //     "get_span_size"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_span_size").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[2].1,
        //     "read_calldata"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "read_calldata").unwrap().ty(&mut store),
            Function(FunctionType::new([I64], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[3].1,
        //     "set_return_data"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "set_return_data").unwrap().ty(&mut store),
            Function(FunctionType::new([I64, I64], []))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[4].1,
        //     "get_ask_count"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_ask_count").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[5].1,
        //     "get_min_count"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_min_count").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[6].1,
        //     "get_prepare_time"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_prepare_time").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[7].1,
        //     "get_execute_time"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_execute_time").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[8].1,
        //     "get_ans_count"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_ans_count").unwrap().ty(&mut store),
            Function(FunctionType::new([], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[9].1,
        //     "ask_external_data"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "ask_external_data").unwrap().ty(&mut store),
            Function(FunctionType::new([I64, I64, I64, I64], []))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[10].1,
        //     "get_external_data_status"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "get_external_data_status").unwrap().ty(&mut store),
            Function(FunctionType::new([I64, I64], [I64]))
        );

        // assert_eq!(
        //     create_import_object(&store, owasm_env.clone()).externs_vec()[11].1,
        //     "read_external_data"
        // );
        assert_eq!(
            create_import_object(&mut store, owasm_env.clone()).get_export("env", "read_external_data").unwrap().ty(&mut store),
            Function(FunctionType::new([I64, I64, I64], [I64]))
        );
    }

    #[test]
    fn test_do_gas() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(()), do_gas(env_mut.as_mut(), 0));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Ok(()), do_gas(env_mut.as_mut(), u32::MAX));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_span_size() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(300), do_get_span_size(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_read_calldata() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(1), do_read_calldata(env_mut.as_mut(), 0));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_read_calldata(env_mut.as_mut(), -1));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_read_calldata(env_mut.as_mut(), 6553600));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_read_calldata(env_mut.as_mut(), i64::MAX));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_read_calldata(env_mut.as_mut(), i64::MIN));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_set_return_data() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(()), do_set_return_data(env_mut.as_mut(), 0, 0));
        gas_limit =
            gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0 as i64));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_set_return_data(env_mut.as_mut(), -1, 0));
        gas_limit =
            gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0 as i64));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_set_return_data(env_mut.as_mut(), i64::MAX, 0));
        gas_limit =
            gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0 as i64));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_set_return_data(env_mut.as_mut(), i64::MIN, 0));
        gas_limit =
            gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0 as i64));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::DataLengthOutOfBound), do_set_return_data(env_mut.as_mut(), 0, -1));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::SpanTooSmallError), do_set_return_data(env_mut.as_mut(), 0, i64::MAX));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::DataLengthOutOfBound), do_set_return_data(env_mut.as_mut(), 0, i64::MIN));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_ask_count() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(10), do_get_ask_count(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_min_count() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(8), do_get_min_count(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_prepare_time() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(100_000), do_get_prepare_time(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_execute_time() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(100_000), do_get_execute_time(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_ans_count() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(8), do_get_ans_count(env_mut.as_mut()));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_ask_external_data() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(()), do_ask_external_data(env_mut.as_mut(), 0, 0, 0, 0));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_ask_external_data(env_mut.as_mut(), 0, 0, -1, 0)
        );
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_ask_external_data(env_mut.as_mut(), 0, 0, i64::MAX, 0)
        );
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_ask_external_data(env_mut.as_mut(), 0, 0, i64::MIN, 0)
        );
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(0));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::DataLengthOutOfBound), do_ask_external_data(env_mut.as_mut(), 0, 0, 0, -1));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::SpanTooSmallError),
            do_ask_external_data(env_mut.as_mut(), 0, 0, 0, i64::MAX)
        );
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::DataLengthOutOfBound),
            do_ask_external_data(env_mut.as_mut(), 0, 0, 0, i64::MIN)
        );
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_ask_external_data(env_mut.as_mut(), 0, 0, i64::MAX, 5)
        );
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS.saturating_add(calculate_read_memory_gas(5));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_get_external_data_status() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(1), do_get_external_data_status(env_mut.as_mut(), 0, 0));
        gas_limit = gas_limit - IMPORTED_FUNCTION_GAS;
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_read_external_data() {
        let mut gas_limit = 2_500_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(1), do_read_external_data(env_mut.as_mut(), 0, 0, 0));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(Err(Error::MemoryOutOfBoundError), do_read_external_data(env_mut.as_mut(), 0, 0, -1));
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_read_external_data(env_mut.as_mut(), 0, 0, i64::MAX)
        );
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        assert_eq!(
            Err(Error::MemoryOutOfBoundError),
            do_read_external_data(env_mut.as_mut(), 0, 0, i64::MIN)
        );
        gas_limit = gas_limit
            - IMPORTED_FUNCTION_GAS.saturating_add(calculate_write_memory_gas(vec![1].len()));
        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }

    #[test]
    fn test_do_ecvrf_verify() {
        let mut gas_limit = 100_000_000_000_000;
        let (owasm_env, instance, mut store) = create_owasm_env();
        let instance_ptr = NonNull::from(&instance);
        owasm_env.set_wasmer_instance(Some(instance_ptr));
        owasm_env.set_gas_left(&mut store, gas_limit);

        //let mut store_mut = store.as_store_mut();

        let env = FunctionEnv::new(&mut store, owasm_env);
        let mut env_mut = env.into_mut(&mut store);

        assert_eq!(Ok(5), do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, 0, 0, 0));
        gas_limit = gas_limit - ECVRF_VERIFY_GAS;

        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        for ptr in [-1, i64::MAX, i64::MIN] {
            assert_eq!(
                Err(Error::MemoryOutOfBoundError),
                do_ecvrf_verify(env_mut.as_mut(), ptr, 0, 0, 0, 0, 0),
                "testing with ptr: {}",
                ptr
            );
            gas_limit = gas_limit - ECVRF_VERIFY_GAS;

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        for ptr in [-1, i64::MAX, i64::MIN] {
            assert_eq!(
                Err(Error::MemoryOutOfBoundError),
                do_ecvrf_verify(env_mut.as_mut(), 0, 0, ptr, 0, 0, 0),
                "testing with ptr: {}",
                ptr
            );
            gas_limit = gas_limit - ECVRF_VERIFY_GAS;

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        for ptr in [-1, i64::MAX, i64::MIN] {
            assert_eq!(
                Err(Error::MemoryOutOfBoundError),
                do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, 0, ptr, 0),
                "testing with ptr: {}",
                ptr
            );
            gas_limit = gas_limit - ECVRF_VERIFY_GAS;

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        for len in [-1, i64::MIN] {
            assert_eq!(
                Err(Error::DataLengthOutOfBound),
                do_ecvrf_verify(env_mut.as_mut(), 0, len, 0, 0, 0, 0),
                "testing with ptr: {}",
                len
            );

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        assert_eq!(
            Err(Error::SpanTooSmallError),
            do_ecvrf_verify(env_mut.as_mut(), 0, i64::MAX, 0, 0, 0, 0),
        );

        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        for len in [-1, i64::MIN] {
            assert_eq!(
                Err(Error::DataLengthOutOfBound),
                do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, len, 0, 0),
                "testing with ptr: {}",
                len
            );

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        assert_eq!(
            Err(Error::SpanTooSmallError),
            do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, i64::MAX, 0, 0),
        );

        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }

        for len in [-1, i64::MIN] {
            assert_eq!(
                Err(Error::DataLengthOutOfBound),
                do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, 0, 0, len),
                "testing with ptr: {}",
                len
            );

            {
                let (owasm_env, mut store) = env_mut.data_and_store_mut();
                assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
            }
        }

        assert_eq!(
            Err(Error::SpanTooSmallError),
            do_ecvrf_verify(env_mut.as_mut(), 0, 0, 0, 0, 0, i64::MAX),
        );

        {
            let (owasm_env, mut store) = env_mut.data_and_store_mut();
            assert_eq!(gas_limit, owasm_env.get_gas_left(&mut store));
        }
    }
}
