
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use dashmap::DashMap;

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

