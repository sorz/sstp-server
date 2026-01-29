// RFC 1549, HDLC FCS
// Reflected CRC-16 with polynomial 0x8408

// FCS lookup table
const fn generate_fcstab() -> [u16; 256] {
    let mut table = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut v = i as u16;
        let mut j = 0;
        while j < 8 {
            v = (v >> 1) ^ (if v & 1 != 0 { 0x8408 } else { 0 });
            j += 1;
        }
        table[i] = v;
        i += 1;
    }
    table
}

const FCSTAB: [u16; 256] = generate_fcstab();

pub(crate) struct Fcs {
    value: u16,
}

impl Fcs {
    pub(crate) fn new() -> Self {
        Self { value: 0xffff }
    }

    pub(crate) fn update(&mut self, byte: u8) {
        let key = ((self.value as u8) ^ byte) as usize;
        self.value = (self.value >> 8) ^ FCSTAB[key];
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
