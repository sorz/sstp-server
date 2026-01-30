// RFC 1549, HDLC FCS
// Reflected CRC-16 with polynomial 0x8408

// FCS lookup table (slice-by-8)
// Ref: https://github.com/HUD-Software/slice-by-8-rs
const fn generate_fcstab() -> [[u16; 256]; 8] {
    let mut table = [[0u16; 256]; 8];

    // Generate the first table (standard)
    let mut i = 0;
    while i < 256 {
        let mut v = i as u16;
        let mut j = 0;
        while j < 8 {
            v = (v >> 1) ^ (if v & 1 != 0 { 0x8408 } else { 0 });
            j += 1;
        }
        table[0][i] = v;
        i += 1;
    }

    // Generate subsequent tables
    // T[k][i] = (T[k-1][i] >> 8) ^ T[0][T[k-1][i] & 0xFF]
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = table[k - 1][i];
            let idx = (prev as usize) & 0xFF;
            table[k][i] = (prev >> 8) ^ table[0][idx];
            i += 1;
        }
        k += 1;
    }

    table
}

const FCSTAB: [[u16; 256]; 8] = generate_fcstab();

pub(crate) struct Fcs {
    value: u16,
}

impl Fcs {
    pub(crate) fn new() -> Self {
        Self { value: 0xffff }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            let key = ((self.value as u8) ^ byte) as usize;
            self.value = (self.value >> 8) ^ FCSTAB[0][key];
        }
    }

    #[inline]
    pub(crate) fn update_u64(&mut self, data: u64) {
        let idx0 = self.value ^ data as u16;
        let idx1 = (self.value >> 8) ^ ((data >> 8) as u16);
        self.value = FCSTAB[7][idx0 as u8 as usize]
            ^ FCSTAB[6][idx1 as u8 as usize]
            ^ FCSTAB[5][(data >> 16) as u8 as usize]
            ^ FCSTAB[4][(data >> 24) as u8 as usize]
            ^ FCSTAB[3][(data >> 32) as u8 as usize]
            ^ FCSTAB[2][(data >> 40) as u8 as usize]
            ^ FCSTAB[1][(data >> 48) as u8 as usize]
            ^ FCSTAB[0][(data >> 56) as u8 as usize];
    }

    pub(crate) fn checksum(&self) -> u16 {
        !self.value
    }
}

#[test]
fn test_fcs() {
    let mut fcs = Fcs::new();
    let bytes: Vec<u8> = (0..255).collect();
    fcs.update(&bytes);
    assert_eq!(0x7859, fcs.checksum());
}

#[test]
fn test_fcs_bytes() {
    let mut fcs_table = Fcs::new();
    let mut fcs_slice = Fcs::new();
    let bytes: Vec<u8> = (0..255).chain(0..255).collect();

    fcs_table.update(&bytes);
    let (prefix, words, suffix) = unsafe { bytes.align_to::<u64>() };
    fcs_slice.update(prefix);
    for &word in words {
        fcs_slice.update_u64(word);
    }
    fcs_slice.update(suffix);

    assert_eq!(fcs_table.checksum(), fcs_slice.checksum());
}
