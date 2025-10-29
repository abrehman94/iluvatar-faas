use std::sync::Arc;
use std::sync::Mutex;

#[derive(Debug)]
pub struct ArcVec<T> {
    inner: Mutex<Vec<Arc<T>>>,
}

impl<T> ArcVec<T> {
    pub fn new() -> Self {
        ArcVec {
            inner: Mutex::new(vec![]),
        }
    }

    pub fn immutable_clone(&self) -> Vec<Arc<T>> {
        self.inner.lock().unwrap().clone()
    }

    pub fn push(&self, data: T) {
        self.inner.lock().unwrap().push(Arc::new(data))
    }

    pub fn push_arc(&self, data: Arc<T>) {
        self.inner.lock().unwrap().push(data)
    }
}

impl<T> Default for ArcVec<T> {
    fn default() -> Self {
        ArcVec {
            inner: Mutex::new(vec![]),
        }
    }
}
