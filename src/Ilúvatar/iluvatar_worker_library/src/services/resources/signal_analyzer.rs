/// Signal Analyzer 
///
/// Semantics are 
///     take a datapoint at a time 
///     build up a buffer of fixed size
///     update subwindows over the buffer 
///     generate signals like average, min, max, normalized min, normalized max
///     over windows 
///
/// Currently supports only i64. Can be extended to support other types.

use std::collections::VecDeque;
use std::sync::Mutex;

trait ValueBounds<T> {
    fn maxval() -> T;
    fn minval() -> T;
}

impl ValueBounds<i64> for i64 {
    fn maxval() -> i64 {
        i64::MAX
    }
    fn minval() -> i64 {
        i64::MIN
    }
}

#[derive(Debug,Clone)]
struct SignalAnalyzerIMutData {
    // copy of imutable data 
    buffer_size: usize,
    win_size: usize,
    win_count: usize,
}

#[derive(Debug,Clone)]
struct SignalAnalyzerMutData<T> 
    where T: Copy
{
    idata: SignalAnalyzerIMutData,

    buffer: VecDeque<T>,
    windows: Vec<Vec<T>>,
    avgs: Vec<T>,
    mins: Vec<T>,
    maxs: Vec<T>,
    avgs_norm_min: Vec<T>,
    avgs_norm_max: Vec<T>,
    buffer_filled_win_init: bool,
}

impl SignalAnalyzerMutData<i64> 
{
    fn update_windows(&mut self) {

        let buffer_vec: Vec<i64> = self.buffer.iter().copied().collect();
        
        // update windows
        for i in 0..self.idata.win_count {
            let window = &buffer_vec[i..i + self.idata.win_size];
            self.windows[i] = window.to_vec();

            let avg = window.iter().map(|e|*e).sum::<i64>() / self.idata.win_size as i64;
            self.avgs[i] = avg;
            if self.buffer_filled_win_init {
                self.mins[i] = self.mins[i].min(avg);
                self.maxs[i] = self.maxs[i].max(avg);

            } 
        }
        
        // special case for first time
        if !self.buffer_filled_win_init {
            for i in 0..self.idata.win_count {
                // for first time mins and maxs are initialized especially 
                // win 0 -> 0: first average only  
                // win 1 -> min/max( 0:1 averages )
                // ...
                // then they are accurately updated based on running avg 
                self.mins[i] = self.avgs[0..i+1].iter().map(|e|*e).reduce(i64::min).unwrap_or(i64::maxval());
                self.maxs[i] = self.avgs[0..i+1].iter().map(|e|*e).reduce(i64::max).unwrap_or(i64::minval());
                println!("{} - avg: {} min: {}", i, self.avgs[i], self.mins[i], );
            }
            self.buffer_filled_win_init = true;
        }

        // updating normalized values 
        for i in 0..self.idata.win_count {
            let avg = self.avgs[i];
            let min_latest = self.mins[self.idata.win_count - 1];
            let max_latest = self.maxs[self.idata.win_count - 1];
            self.avgs_norm_min[i] = if min_latest != 0 { avg / min_latest } else { 0 };
            self.avgs_norm_max[i] = if max_latest != 0 { avg / max_latest } else { 0 };
        }
    }
}


#[derive(Debug)]
pub struct SignalAnalyzer<T> 
    where T: Copy
{
    idata: SignalAnalyzerIMutData,
    
    data: Mutex<SignalAnalyzerMutData<T>>,
}

impl SignalAnalyzer<i64> 
//   where T: Clone + Default + ValueBounds<T> + Copy
{
    pub fn new(buffer_size: usize) -> Self {
        let win_size = buffer_size / 2;
        let win_count = (buffer_size - win_size) + 1;
        
        let idata = SignalAnalyzerIMutData {
            buffer_size,
            win_size,
            win_count,
        };
        let data = SignalAnalyzerMutData::<i64> {
            idata: idata.clone(),

            buffer: VecDeque::with_capacity(buffer_size),
            windows: vec![vec![Default::default(); win_size]; win_count],
            avgs: vec![Default::default(); win_count],
            mins: vec![i64::maxval(); win_count],
            maxs: vec![i64::minval(); win_count],
            avgs_norm_min: vec![Default::default(); win_count],
            avgs_norm_max: vec![Default::default(); win_count],
            buffer_filled_win_init: false,
        };

        SignalAnalyzer {
            idata,

            data: Mutex::new(data),
        }
    }

    pub fn push(&self, val: i64) {
        let mut data = self.data.lock().unwrap();
        data.buffer.push_back(val);
        if data.buffer.len() > self.idata.buffer_size {
            data.buffer.pop_front();
        }

        if data.buffer.len() >= self.idata.buffer_size {
            data.update_windows();
        }
    }
 
    pub fn get_n(&self) -> usize {
        self.data.lock().unwrap().buffer.len()
    }

    pub fn get_nth_max(&self, index: isize) -> i64 {
        self.get_at(&self.data.lock().unwrap().maxs, index)
    }

    pub fn get_nth_min(&self, index: isize) -> i64 {
        self.get_at(&self.data.lock().unwrap().mins, index)
    }

    pub fn get_nth_avg(&self, index: isize) -> i64 {
        self.get_at(&self.data.lock().unwrap().avgs, index)
    }

    pub fn get_nth_minnorm_avg(&self, index: isize) -> i64 {
        self.get_at(&self.data.lock().unwrap().avgs_norm_min, index)
    }

    fn get_at(&self, vec: &Vec<i64>, index: isize) -> i64 {
        let idx;  
        if index < 0 {
            idx = (vec.len() as isize + index) as usize;
        } else {
            idx = index as usize;
        }
        vec.get(idx).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod signal_analyzer_tests {
    use super::*;

    #[test]
    fn test_basic_push_and_average() {
        let sa = SignalAnalyzer::new(6);
        sa.push(20);
        sa.push(20);
        sa.push(30);
        sa.push(40);
        sa.push(50);
        sa.push(60);

        // Window size is 3, so with buffer_size=6, we get 4 windows: 
        // [20,20,30], [20,30,40], [30,40,50], [40,50,60]
        //
        // Averages: [23, 30, 40, 50]
        // Mins: [23, 23, 23, 23]
        // Max: [23, 30, 40, 50]
        // Normalized Mins: [1, 1, 2, 2]
        assert_eq!(sa.get_n(), 6);

        assert_eq!( sa.get_nth_avg(0)          , 23);
        assert_eq!( sa.get_nth_avg(-1)         , 50);

        assert_eq!( sa.get_nth_min(0)          , 23);
        assert_eq!( sa.get_nth_min(-1)         , 23);

        assert_eq!( sa.get_nth_max(0)          , 23);
        assert_eq!( sa.get_nth_max(-1)         , 50);

        assert_eq!( sa.get_nth_minnorm_avg(0)  , 1);
        assert_eq!( sa.get_nth_minnorm_avg(-1) , 2);
    }
}

impl Clone for SignalAnalyzer<i64> {
    fn clone(&self) -> Self {
        SignalAnalyzer {
            idata: self.idata.clone(),
            data: Mutex::new(self.data.lock().unwrap().clone()),
        }
    }
}

