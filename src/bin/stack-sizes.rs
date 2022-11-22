use std::path::Path;

use clap::{App, Arg};

const ABOUT: &str = "Prints the stack usage of each function in an ELF file.";

fn main() -> Result<(), failure::Error>  {
    let matches = App::new("stack-sizes")
        .about(ABOUT)
        .version(env!("CARGO_PKG_VERSION"))
        .arg(
            Arg::with_name("ELF")
                .help("ELF file to analyze")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("obj")
                .help("obj file to analyze")
                .required(false)
                .index(2),
        )
        .get_matches();

    let path = matches.value_of("ELF").unwrap();
    let obj_opt = matches.value_of("obj");

    match obj_opt {
        None => stack_sizes::run(Path::new(path)),
        Some(ref obj) => stack_sizes::run_exec(Path::new(path), Path::new(obj)),
    }
}
