use crate::*;

pub fn add_checks() {
    // check::add_check(
    //     "LIB_001",
    //     "Ensure \"libhardened_malloc\" hardened malloc is used system wide",
    //     vec!["malloc"],
    //     malloc::has_libhardened_malloc,
    //     vec![malloc::init_ld_so_preload],
    // );
    check::add_check(
        "LIB_001",
        "Ensure \"scudo\" hardened malloc is used system wide",
        vec!["malloc"],
        malloc::has_scudo_malloc,
        vec![malloc::init_ld_so_preload],
    );
}
