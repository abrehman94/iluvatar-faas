use std::vec::Vec;
use crate::bpf_intf::cpumask;

pub fn set_cpumask( mask: &mut cpumask, core: &u32 ){
    let mut bi: u32 = 0;
    let mut bit: u32 = 0;
    let n = std::mem::size_of::<u64>() as u32 * 8; // size in bytes * number of bits in a byte 
    bi = core / n;
    bit = core%n;
    mask.bits[bi as usize] |= (1<<bit);
}

pub fn vec_to_cpumask( cores: &Vec<u32> ) -> cpumask {
    let mut cm = default_cpumask();

    for core in cores.into_iter() {
        set_cpumask(&mut cm, core);
    }

    cm
}

// todo: find a better way to replace 128 it should
// take the value from intf autogenerate struct cpumask
pub fn default_cpumask() -> cpumask {
    cpumask{
        bits: [0; 128]
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_vec_to_cpumask_base() {
        let v: Vec<u32> = (0..4).into_iter().collect(); 
        let cpumask = vec_to_cpumask( &v );

        let mut ans = default_cpumask();
        // 1111 -> 0xf 
        ans.bits[0] = 0xf;
        
        for i in 0..ans.bits.len(){
            assert_eq!(cpumask.bits[i], ans.bits[i]);
        }
    }

    #[test]
    fn test_vec_to_cpumask_next_byte() {
        let v: Vec<u32> = (8..12).into_iter().collect(); 
        let cpumask = vec_to_cpumask( &v );

        let mut ans = default_cpumask();
        // 0b1111_0000_0000 -> 0xf00 - that is bit[1] should be 0xf
        ans.bits[0] = 0xf00;
        
        for i in 0..ans.bits.len(){
            assert_eq!(cpumask.bits[i], ans.bits[i]);
        }
    }
}













