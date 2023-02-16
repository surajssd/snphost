// SPDX-License-Identifier: Apache-2.0

use crate::certs::*;

use anyhow::{Context, Result};
use sev::firmware::host::Firmware;
use structopt::StructOpt;

mod certs;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpHost {
    #[structopt(subcommand)]
    pub cmd: SnpHostCmd,

    #[structopt(short, long, help = "Don't print anything to the console")]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV-SNP environment")]
enum SnpHostCmd {
    #[structopt(
        about = "Subcommands related to the viewing/manipulation of the SEV-SNP certificate chain"
    )]
    Certs(CertsCmd),
}

fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::from_args();

    let status = match snphost.cmd {
        SnpHostCmd::Certs(subcmd) => certs::cmd(subcmd),
    };

    if let Err(ref e) = status {
        if !snphost.quiet {
            eprintln!("ERROR: {}", e);
            e.chain()
                .skip(1)
                .for_each(|cause| eprintln!("because: {}", cause));
        }
    }

    status
}

pub fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open firmware device")
}
