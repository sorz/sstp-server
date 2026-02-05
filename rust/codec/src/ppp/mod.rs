mod decode;
mod encode;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;

pub(crate) use decode::{PartialFrame, decode_frames};
pub(crate) use encode::encode_frame;

#[test]
fn test_encode_decode() {
    let mut f1 = [0u8; 10];
    let mut f2 = [0u8; 500];
    let mut f3 = [0u8; 2000];
    rand::fill(&mut f1);
    rand::fill(&mut f2);
    rand::fill(&mut f3);

    let mut ppp = vec![0u8; 4000];
    let mut len = 0;
    len += encode_frame(true, &f1, &mut ppp[len..]);
    len += encode_frame(false, &f1, &mut ppp[len..]);
    len += encode_frame(true, &f2, &mut ppp[len..]);
    len += encode_frame(false, &f2, &mut ppp[len..]);
    len += encode_frame(false, &f3, &mut ppp[len..]);
    let ppp_len = (10 + 500) * 2 + 2000;
    assert!(len > ppp_len);
    assert!(len < ppp.len());
    ppp.resize(len, 0);

    let mut partial = decode::PartialFrame::default();
    let mut sstp = vec![0u8; 4000];
    let n = decode_frames(&mut partial, &ppp, &mut sstp, false);
    assert_eq!(n, ppp_len + 4 * 5);

    assert_eq!([0x10, 0, 0, 14], sstp[..4]);
    assert_eq!(f1, sstp[4..14]);

    assert_eq!([0x10, 0, 0, 14], sstp[14..18]);
    assert_eq!(f1, sstp[18..28]);

    assert_eq!([0x10, 0, 1, 248], sstp[28..32]);
    assert_eq!(f2, sstp[32..532]);

    assert_eq!([0x10, 0, 1, 248], sstp[532..536]);
    assert_eq!(f2, sstp[536..1036]);

    assert_eq!([0x10, 0, 7, 212], sstp[1036..1040]);
    assert_eq!(f3, sstp[1040..3040]);
}
