use cfg_aliases::cfg_aliases;

fn main() {
    cfg_aliases! {
        avx512_encode: {
            all(
                target_arch = "x86_64",
                target_feature = "avx",
                target_feature = "avx512f",
                target_feature = "avx512bw",
                target_feature = "avx512vl",
                target_feature = "avx512vbmi2"
            )
        },
        avx512_decode: {
            all(
                target_arch = "x86_64",
                target_feature = "avx512f",
                target_feature = "avx512bw",
                target_feature = "avx512vbmi2"
            )
        },
    }
}
