fn main() {
    ::pkg_config::probe_library("munge")
        .unwrap_or_else(|err| panic!(
            "`munge-sys` requires `munge` to be installed: {}", err,
        ));
}
