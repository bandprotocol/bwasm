use crate::error::Error;

use std::borrow::{Borrow, BorrowMut};
use std::ptr::NonNull;
use std::sync::{Arc, RwLock};
use wasmer::{AsStoreMut, Instance, Memory};
use wasmer_middlewares::metering::{get_remaining_points, set_remaining_points, MeteringPoints};

pub trait Querier {
    /// Returns the maximum span size value.
    fn get_span_size(&self) -> i64;
    /// Returns user calldata, or returns error from VM runner.
    fn get_calldata(&self) -> Result<Vec<u8>, Error>;
    /// Sends the desired return `data` to VM runner, or returns error from VM runner.
    fn set_return_data(&self, data: &[u8]) -> Result<(), Error>;
    /// Returns the current "ask count" value.
    fn get_ask_count(&self) -> i64;
    /// Returns the current "min count" value.
    fn get_min_count(&self) -> i64;
    /// Returns the prepare block time of the request.
    fn get_prepare_time(&self) -> i64;
    /// Returns the execute block time of the request, or error from VM runner if called on wrong period.
    fn get_execute_time(&self) -> Result<i64, Error>;
    /// Returns the current "ans count" value, or error from VM runner if called on wrong period.
    fn get_ans_count(&self) -> Result<i64, Error>;
    /// Issues a new external data request to VM runner, with the specified ids and calldata.
    fn ask_external_data(&self, eid: i64, did: i64, data: &[u8]) -> Result<(), Error>;
    /// Returns external data status for data id `eid` from validator index `vid`.
    fn get_external_data_status(&self, eid: i64, vid: i64) -> Result<i64, Error>;
    /// Returns data span with the data id `eid` from validator index `vid`.
    fn get_external_data(&self, eid: i64, vid: i64) -> Result<Vec<u8>, Error>;
}

pub struct ContextData<Q: Querier> {
    querier: Q,
    /// A non-owning link to the wasmer instance
    wasmer_instance: Option<NonNull<Instance>>,
}

impl<Q: Querier> ContextData<Q> {
    pub fn new(querier: Q) -> Self {
        ContextData::<Q> { wasmer_instance: None, querier }
    }
}

pub struct Environment<Q>
where
    Q: Querier + 'static,
{
    data: Arc<RwLock<ContextData<Q>>>,
}

impl<Q: Querier + 'static> Clone for Environment<Q> {
    fn clone(&self) -> Self {
        Self { data: self.data.clone() }
    }
}
unsafe impl<Q: Querier> Send for Environment<Q> {}
unsafe impl<Q: Querier> Sync for Environment<Q> {}

impl<Q> Environment<Q>
where
    Q: Querier + 'static,
{
    pub fn new(q: Q) -> Self {
        Self { data: Arc::new(RwLock::new(ContextData::new(q))) }
    }

    pub fn with_querier_from_context<C, R>(&self, callback: C) -> R
    where
        C: FnOnce(&Q) -> R,
    {
        self.with_context_data(|context_data| callback(&context_data.querier))
    }

    /// Creates a back reference from a contact to its partent instance
    pub fn set_wasmer_instance(&self, instance: Option<NonNull<Instance>>) {
        self.with_context_data_mut(|data| {
            data.wasmer_instance = instance;
        })
    }

    pub fn with_wasmer_instance<C, R>(&self, callback: C) -> Result<R, Error>
    where
        C: FnOnce(&Instance) -> Result<R, Error>,
    {
        self.with_context_data(|context_data| match context_data.wasmer_instance {
            Some(instance_ptr) => {
                let instance_ref = unsafe { instance_ptr.as_ref() };
                callback(instance_ref)
            }
            None => Err(Error::UninitializedContextData),
        })
    }

    fn with_context_data<C, R>(&self, callback: C) -> R
    where
        C: FnOnce(&ContextData<Q>) -> R,
    {
        let guard = self.data.as_ref().read().unwrap();
        let context_data = guard.borrow();
        callback(context_data)
    }

    fn with_context_data_mut<C, R>(&self, callback: C) -> R
    where
        C: FnOnce(&mut ContextData<Q>) -> R,
    {
        let mut guard = self.data.as_ref().write().unwrap();
        let context_data = guard.borrow_mut();
        callback(context_data)
    }

    pub fn get_gas_left(&self, store: &mut impl AsStoreMut) -> u64 {
        self.with_wasmer_instance(|instance| {
            Ok(match get_remaining_points(store, instance) {
                MeteringPoints::Remaining(count) => count,
                MeteringPoints::Exhausted => 0,
            })
        })
        .expect("Wasmer instance is not set. This is a bug in the lifecycle.")
    }

    pub fn set_gas_left(&self, store: &mut impl AsStoreMut, new_value: u64) {
        self.with_wasmer_instance(|instance| {
            set_remaining_points(store, instance, new_value);
            Ok(())
        })
        .expect("Wasmer instance is not set. This is a bug in the lifecycle.")
    }

    pub fn decrease_gas_left(&self, store: &mut impl AsStoreMut, gas: u64) -> Result<(), Error> {
        let gas_left = self.get_gas_left(store);
        if gas > gas_left {
            Err(Error::OutOfGasError)
        } else {
            self.set_gas_left(store, gas_left.saturating_sub(gas));
            Ok(())
        }
    }

    pub fn memory(&self) -> Result<Memory, Error> {
        self.with_context_data(|data| match data.wasmer_instance {
            Some(instance_ptr) => {
                let instance_ref = unsafe { instance_ptr.as_ref() };
                let mut memories: Vec<Memory> =
                    instance_ref.exports.iter().memories().map(|pair| pair.1.clone()).collect();

                match memories.pop() {
                    Some(m) => Ok(m),
                    None => Err(Error::MemoryOutOfBoundError),
                }
            }
            _ => Err(Error::BadMemorySectionError),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        process::Command,
    };

    use tempfile::NamedTempFile;
    use wasmer::{Engine, imports, Singlepass, Store};

    use crate::{
        cache::{Cache, CacheOptions},
        store::make_store,
    };

    use super::*;

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
    fn test_env_querier() {
        let env = Environment::new(MockQuerier {});
        assert_eq!(300, env.with_querier_from_context(|querier| querier.get_span_size()));
    }

    #[test]
    fn test_env_wasmer_instance() {
        let env = Environment::new(MockQuerier {});
        assert_eq!(
            Error::UninitializedContextData,
            env.with_wasmer_instance(|_| { Ok(()) }).unwrap_err()
        );

        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );
        let compiler = Singlepass::new();
        let engine: Engine = compiler.into();
        let mut store = Store::new(engine);
        let import_object = imports! {};
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let (instance, _) = cache.get_instance(&wasm, &mut store, &import_object).unwrap();
        env.set_wasmer_instance(Some(NonNull::from(&instance)));
        assert_eq!(Ok(()), env.with_wasmer_instance(|_| { Ok(()) }));
    }

    #[test]
    fn test_env_gas() {
        let env = Environment::new(MockQuerier {});
        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );
        let mut store = make_store();
        let import_object = imports! {};
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let (instance, _) = cache.get_instance(&wasm, &mut store, &import_object).unwrap();
        env.set_wasmer_instance(Some(NonNull::from(&instance)));

        assert_eq!(0, env.get_gas_left(&mut store));

        env.set_gas_left(&mut store, 10);
        assert_eq!(10, env.get_gas_left(&mut store));

        assert_eq!(Error::OutOfGasError, env.decrease_gas_left(&mut store, 11).unwrap_err());
        assert_eq!(Ok(()), env.decrease_gas_left(&mut store, 3));
        assert_eq!(7, env.get_gas_left(&mut store));
    }
}
