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

    #[inline]
    pub(crate) fn update(&mut self, byte: u8) {
        let key = ((self.value as u8) ^ byte) as usize;
        self.value = (self.value >> 8) ^ FCSTAB[0][key];
    }

    pub(crate) fn update_bytes(&mut self, data: &[u8]) {
        // Safety: transmutes u8 to u64 is safe
        let (prefix, words, suffix) = unsafe { data.align_to::<u64>() };
        for &b in prefix {
            self.update(b);
        }
        self.value = words.iter().fold(self.value, |fcs, &word| {
            let idx0 = fcs ^ word as u16;
            let idx1 = (fcs >> 8) ^ ((word >> 8) as u16);
            FCSTAB[7][idx0 as u8 as usize]
                ^ FCSTAB[6][idx1 as u8 as usize]
                ^ FCSTAB[5][(word >> 16) as u8 as usize]
                ^ FCSTAB[4][(word >> 24) as u8 as usize]
                ^ FCSTAB[3][(word >> 32) as u8 as usize]
                ^ FCSTAB[2][(word >> 40) as u8 as usize]
                ^ FCSTAB[1][(word >> 48) as u8 as usize]
                ^ FCSTAB[0][(word >> 56) as u8 as usize]
        });
        for &b in suffix {
            self.update(b);
        }
    }

    pub(crate) fn checksum(&self) -> u16 {
        !self.value
    }
}

#[test]
fn test_fcs() {
    let mut fcs = Fcs::new();
    for i in 0..255 {
        fcs.update(i as u8);
    }
    assert_eq!(0x7859, fcs.checksum());
}

#[test]
fn test_fcs_bytes() {
    let mut fcs_scalar = Fcs::new();
    let mut fcs_bytes = Fcs::new();
    let bytes: Vec<u8> = (0..255).chain(0..255).collect();

    for &b in &bytes {
        fcs_scalar.update(b);
    }
    fcs_bytes.update_bytes(&bytes);

    assert_eq!(fcs_scalar.checksum(), fcs_bytes.checksum());
}
