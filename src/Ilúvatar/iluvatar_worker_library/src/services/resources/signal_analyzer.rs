/// Signal Analyzer 
///
/// Semantics are 
///     take a datapoint at a time 
///     build up a buffer of fixed size
///     update subwindows over the buffer 
///     generate signals like average, min, max, normalized min, normalized max
///     over windows 
///
/// Currently supports only i32. Can be extended to support other types.

use std::collections::VecDeque;
use std::sync::Mutex;

pub const const_DEFAULT_BUFFER_SIZE: usize = 2; // 6 - is too long, signal has too much lag 

trait ValueBounds<T> {
    fn maxval() -> T;
    fn minval() -> T;
}

impl ValueBounds<i32> for i32 {
    fn maxval() -> i32 {
        i32::MAX
    }
    fn minval() -> i32 {
        i32::MIN
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

impl SignalAnalyzerMutData<i32> 
{
    fn update_windows(&mut self) {

        let buffer_vec: Vec<i32> = self.buffer.iter().copied().collect();
        
        // update windows
        for i in 0..self.idata.win_count {
            let window = &buffer_vec[i..i + self.idata.win_size];
            self.windows[i] = window.to_vec();
            
            // if the sum overflows for whatever reason for a given window 
            // the avg will be set to zero with commented out snippet 
            //
            // an avg of zero at runtime for no reason can lead to 
            // all sorts of problems and it would be difficult to debug if a problem 
            // happens because of this zero - it is easier to see a panic 
            // a sum overflow in the first place indicates a problem - solve that 
            //
            // let sum = window.iter().try_fold(0i32, |acc, &x| acc.checked_add(x));
            // let avg;
            // if let Some(sum) = sum {
            //     avg = sum / self.idata.win_size as i32;
            // } else {
            //     avg = 0;
            // }            

            let avg = window.iter().map(|e|*e).sum::<i32>() / self.idata.win_size as i32;

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
                self.mins[i] = self.avgs[0..i+1].iter().map(|e|*e).reduce(i32::min).unwrap_or(i32::maxval());
                self.maxs[i] = self.avgs[0..i+1].iter().map(|e|*e).reduce(i32::max).unwrap_or(i32::minval());
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

impl SignalAnalyzer<i32> 
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
        let data = SignalAnalyzerMutData::<i32> {
            idata: idata.clone(),

            buffer: VecDeque::with_capacity(buffer_size),
            windows: vec![vec![Default::default(); win_size]; win_count],
            avgs: vec![Default::default(); win_count],
            mins: vec![i32::maxval(); win_count],
            maxs: vec![i32::minval(); win_count],
            avgs_norm_min: vec![Default::default(); win_count],
            avgs_norm_max: vec![Default::default(); win_count],
            buffer_filled_win_init: false,
        };

        SignalAnalyzer {
            idata,

            data: Mutex::new(data),
        }
    }
    
    pub fn reset(&self){
        let mut data = self.data.lock().unwrap();
        data.buffer.clear();
        data.windows.clear();
        data.avgs.clear();
        data.mins.clear();
        data.maxs.clear();
        data.avgs_norm_min.clear();
        data.avgs_norm_max.clear();
        data.buffer_filled_win_init = false;
    }

    pub fn push(&self, val: i32) {
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

    pub fn get_nth_max(&self, index: isize) -> i32 {
        self.get_at(&self.data.lock().unwrap().maxs, index)
    }

    pub fn get_nth_min(&self, index: isize) -> i32 {
        self.get_at(&self.data.lock().unwrap().mins, index)
    }

    pub fn get_nth_avg(&self, index: isize) -> i32 {
        self.get_at(&self.data.lock().unwrap().avgs, index)
    }

    pub fn get_nth_minnorm_avg(&self, index: isize) -> i32 {
        self.get_at(&self.data.lock().unwrap().avgs_norm_min, index)
    }

    fn get_at(&self, vec: &Vec<i32>, index: isize) -> i32 {
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
        let sa = SignalAnalyzer::new(const_DEFAULT_BUFFER_SIZE);
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
        assert_eq!(sa.get_n(), const_DEFAULT_BUFFER_SIZE);

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

impl Clone for SignalAnalyzer<i32> {
    fn clone(&self) -> Self {
        SignalAnalyzer {
            idata: self.idata.clone(),
            data: Mutex::new(self.data.lock().unwrap().clone()),
        }
    }
}

impl Default for SignalAnalyzer<i32> {
    fn default() -> Self {
        SignalAnalyzer::new(const_DEFAULT_BUFFER_SIZE)
    }
}



