use std::{
    borrow::BorrowMut,
    sync::{Arc, RwLock},
};

use crate::checksum::Checksum;
use crate::error::Error;

use clru::CLruCache;
use wasmer::{Instance, Module, Store};

/// An in-memory module cache
pub struct InMemoryCache {
    modules: CLruCache<Checksum, Module>,
}

impl InMemoryCache {
    pub fn new(max_entries: u32) -> Self {
        InMemoryCache { modules: CLruCache::new(max_entries as usize) }
    }

    pub fn store(&mut self, checksum: &Checksum, module: Module) -> Option<Module> {
        self.modules.put(*checksum, module)
    }

    /// Looks up a module in the cache and creates a new module
    pub fn load(&mut self, checksum: &Checksum) -> Option<Module> {
        self.modules.get(checksum).cloned()
    }
}

#[derive(Clone, Debug)]
pub struct CacheOptions {
    pub cache_size: u32,
}

pub struct Cache {
    memory_cache: Arc<RwLock<InMemoryCache>>,
}

impl Cache {
    pub fn new(options: CacheOptions) -> Self {
        let CacheOptions { cache_size } = options;

        Self { memory_cache: Arc::new(RwLock::new(InMemoryCache::new(cache_size))) }
    }

    fn with_in_memory_cache<C, R>(&mut self, callback: C) -> R
    where
        C: FnOnce(&mut InMemoryCache) -> R,
    {
        let mut guard = self.memory_cache.as_ref().write().unwrap();
        let in_memory_cache = guard.borrow_mut();
        callback(in_memory_cache)
    }

    pub fn get_instance(
        &mut self,
        wasm: &[u8],
        store: &mut Store,
        import_object: &wasmer::Imports,
    ) -> Result<(wasmer::Instance, bool), Error> {
        let checksum = Checksum::generate(wasm);
        self.with_in_memory_cache(|in_memory_cache| {
            // lookup cache
            if let Some(module) = in_memory_cache.load(&checksum) {
                return Ok((Instance::new(store, &module, &import_object).unwrap(), true));
            }

            // recompile
            let module = Module::new(store, &wasm).map_err(|_| Error::InstantiationError)?;
            let instance =
                Instance::new(store, &module, &import_object).map_err(|_| Error::InstantiationError)?;

            in_memory_cache.store(&checksum, module);

            Ok((instance, false))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;
    use tempfile::NamedTempFile;
    use wasmer::imports;
    use crate::store::make_store;

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

    fn get_instance_without_err(cache: &mut Cache, wasm: &[u8]) -> (wasmer::Instance, bool) {
        let mut store = make_store();
        let import_object = imports! {};

        match cache.get_instance(&wasm, &mut store, &import_object) {
            Ok((instance, is_hit)) => (instance, is_hit),
            Err(_) => panic!("Fail to get instance"),
        }
    }

    #[test]
    fn test_cache_catch() {
        let mut cache = Cache::new(CacheOptions { cache_size: 10000 });
        let wasm = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
              )"#,
        );

        let wasm2 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo2 (export "foo2"))
              )"#,
        );

        let (instance1, is_hit) = get_instance_without_err(&mut cache, &wasm);
        assert_eq!(false, is_hit);

        let (instance2, is_hit) = get_instance_without_err(&mut cache, &wasm);
        assert_eq!(true, is_hit);

        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(false, is_hit);

        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm);
        assert_eq!(true, is_hit);

        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(true, is_hit);

        let ser1 = match instance1.module().serialize() {
            Ok(r) => r,
            Err(_) => panic!("Fail to serialize module"),
        };

        let ser2 = match instance2.module().serialize() {
            Ok(r) => r,
            Err(_) => panic!("Fail to serialize module"),
        };

        assert_eq!(ser1, ser2);
    }

    #[test]
    fn test_cache_size() {
        let mut cache = Cache::new(CacheOptions { cache_size: 2 });
        let wasm1 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo (export "foo"))
              )"#,
        );

        let wasm2 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo2 (export "foo2"))
              )"#,
        );

        let wasm3 = wat2wasm(
            r#"(module
                (func $execute (export "execute"))
                (func $prepare (export "prepare"))
                (func $foo3 (export "foo3"))
              )"#,
        );

        // miss [_ _] => [1 _]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(false, is_hit);

        // miss [1 _] => [2 1]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(false, is_hit);

        // miss [2 1] => [3 2]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm3);
        assert_eq!(false, is_hit);

        // hit [3 2] => [2 3]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(true, is_hit);

        // miss [2 3] => [1 2]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(false, is_hit);

        // hit [1 2] => [2 1]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm2);
        assert_eq!(true, is_hit);

        // miss [2 1] => [3 2]
        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm3);
        assert_eq!(false, is_hit);

        cache = Cache::new(CacheOptions { cache_size: 0 });

        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(false, is_hit);

        let (_, is_hit) = get_instance_without_err(&mut cache, &wasm1);
        assert_eq!(false, is_hit);
    }
}
