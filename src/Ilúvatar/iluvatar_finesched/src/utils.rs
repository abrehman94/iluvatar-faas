use std::vec::Vec;
use crate::bpf_intf::cpumask;

pub fn set_cpumask( mask: &mut cpumask, core: &u32 ){
    let mut bi: u32 = 0;
    let mut bit: u32 = 0;
    bi = core / 8;
    bit = core%8;
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
    fn test_vec_to_cpumask() {
        let v: Vec<u32> = (0..4).into_iter().collect(); 
        let cpumask = vec_to_cpumask( &v );

        let mut ans = default_cpumask();
        // 1111 -> 0xf 
        ans.bits[0] = 0xf;
        
        for i in 0..ans.bits.len(){
            assert_eq!(cpumask.bits[i], ans.bits[i]);
        }
    }
}













