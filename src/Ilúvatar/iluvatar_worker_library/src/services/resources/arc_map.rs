
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicI32;
use std::sync::Mutex;
use dashmap::DashMap;

pub struct ClonableMutex<T> 
    where T: Clone + Default
{
    pub value: Mutex<T>,
}

impl <T> Default for ClonableMutex<T> 
    where T: Clone + Default
{
    fn default() -> Self {
        ClonableMutex {
            value: Mutex::new(T::default()),
        }
    }
}

impl<T> ClonableMutex<T> 
    where T: Clone + Default
{
    pub fn new(value: T) -> Self {
        ClonableMutex {
            value: Mutex::new(value),
        }
    }
}

impl<T> Clone for ClonableMutex<T> 
    where T: Clone + Default
{
    fn clone(&self) -> Self {
        ClonableMutex {
            value: Mutex::new(self.value.lock().unwrap().clone()),
        }
    }
}

/////////////////////////////////////////////////////////////////////////
/// Ugly Code - Can use procedural macros to generate clonable atomics for
/// each atomic type - needs it's own crate - maybe some other time 

pub struct ClonableAtomicU32 {
    pub value: AtomicU32,
}

impl ClonableAtomicU32 {
    pub fn new(value: u32) -> Self {
        ClonableAtomicU32 {
            value: AtomicU32::new(value),
        }
    }
}

impl Default for ClonableAtomicU32 {
    fn default() -> Self {
        ClonableAtomicU32 {
            value: AtomicU32::new(0),
        }
    }
}

impl Clone for ClonableAtomicU32 {
    fn clone(&self) -> Self {
        ClonableAtomicU32 {
            value: AtomicU32::new(self.value.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }
}

pub struct ClonableAtomicI32 {
    pub value: AtomicI32,
}

impl ClonableAtomicI32 {
    pub fn new(value: i32) -> Self {
        ClonableAtomicI32 {
            value: AtomicI32::new(value),
        }
    }
}

impl Default for ClonableAtomicI32 {
    fn default() -> Self {
        ClonableAtomicI32 {
            value: AtomicI32::new(0),
        }
    }
}

impl Clone for ClonableAtomicI32 {
    fn clone(&self) -> Self {
        ClonableAtomicI32 {
            value: AtomicI32::new(self.value.load(std::sync::atomic::Ordering::Relaxed)),
        }
    }
}

/// Ugly Code ends 
///////////////////////////////////////



#[derive(Debug)]
pub struct ArcMap<K,V> 
    where K: Eq + std::hash::Hash + Clone,
          V: Clone + Default
{
    pub map: DashMap<K, Arc<V>>,
}

impl<K,V> Clone for ArcMap<K, V> 
    where K: Eq + std::hash::Hash + Clone,
          V: Clone + Default
{
    fn clone(&self) -> Self {
        ArcMap {
            map: self.map.clone(),
        }
    }
}

impl <K, V> ArcMap<K, V> 
    where K: Eq + std::hash::Hash + Clone,
          V: Clone + Default
{
    pub fn new() -> Self {
        ArcMap {
            map: DashMap::new(),
        }
    }

    pub fn get(&self, key: &K) -> Option<Arc<V>> {
        self.map.get(key).map(|v| v.value().clone())
    }

    pub fn get_or_create( &self, key: &K ) -> Arc<V> {
        match self.map.get( key ) {
            Some( v ) => (*v.value()).clone(),
            None => {
                let val: Arc<V> = Arc::new(Default::default());
                self.map.insert( (*key).clone(), val.clone() );
                val 
            }
        }
    }
}

impl<K,V> Default for ArcMap<K, V>
    where K: Eq + std::hash::Hash + Clone,
          V: Clone + Default
{
    fn default() -> Self {
        ArcMap {
            map: DashMap::new(),
        }
    }
}


