use crate::check;
use crate::check::Severity;
use crate::modules::malloc;

pub fn add_checks() {
    // check::Check::new(
    //     "LIB_001",
    //     "Ensure \"libhardened_malloc\" hardened malloc is used system wide",
    //     vec!["malloc", "workstation"],
    //     malloc::has_libhardened_malloc,
    //     vec![malloc::init_ld_so_preload],
    // ).register();

    check::Check::new(
        "LIB_001",
        "Ensure \"scudo\" hardened malloc is used system wide",
        Severity::Medium,
        vec!["malloc", "workstation"],
        malloc::has_scudo_malloc,
        vec![malloc::init_ld_so_preload],
    )
    .with_description("Scudo hardened allocators deterministically detect or mitigate common heap-corruption primitives: use-after-free, double-free, out-of-bounds writes, type confusion across slabs; that the default glibc allocator leaves exploitable. Without one, heap bugs in any setuid or network-facing process are far easier to weaponize. Defense-in-depth to prevent bug exploitation.")
    .register();
}
