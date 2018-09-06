
pub(crate) struct AesContext {
    erk: [u32; 64],
    drk: [u32; 64],
    nr: isize,
}
