// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(StructOpt)]
pub enum CertsCmd {
    Set(set::Args),
}

pub fn cmd(cmd: CertsCmd) -> Result<()> {
    match cmd {
        CertsCmd::Set(args) => set::cmd(args),
    }
}

mod set {
    use super::*;

    use std::fmt;
    use std::fs::read;
    use std::path::PathBuf;

    use sev::firmware::host::types::{CertTableEntry, SnpCertType, SnpExtConfig};

    #[derive(StructOpt, fmt::Debug)]
    pub struct Args {
        #[structopt(long, help = "The AMD Root Key (ARK)")]
        pub ark: PathBuf,

        #[structopt(long, help = "The AMD Signing Key (ASK)")]
        pub ask: PathBuf,

        #[structopt(long, help = "The Versioned Chip Endorsement Key (VCEK)")]
        pub vcek: PathBuf,
    }

    pub fn cmd(args: Args) -> Result<()> {
        let mut sev = firmware().context("unable to open SEV firmware device")?;

        let mut entries: Vec<CertTableEntry> = Vec::new();

        let ark = read(args.ark).context("unable to read ARK file")?;
        let ask = read(args.ask).context("unable to read ASK file")?;
        let vcek = read(args.vcek).context("unable to read VCEK file")?;

        let size = ark.len() + ask.len() + vcek.len();

        entries.push(CertTableEntry {
            cert_type: SnpCertType::ARK,
            data: ark,
        });

        entries.push(CertTableEntry {
            cert_type: SnpCertType::ASK,
            data: ask,
        });

        entries.push(CertTableEntry {
            cert_type: SnpCertType::VCEK,
            data: vcek,
        });

        /*
         * The certificate buffer size must be aligned on a 4kB page boundary.
         */
        let size = if size < 0x1000 {
            0x1000
        } else {
            ((size % 0x1000) + 1) * 0x1000
        };

        let config = SnpExtConfig {
            config: None,
            certs: Some(entries),
            certs_len: size as u32,
        };

        sev.snp_set_ext_config(&config)
            .context("SNP_SET_EXT_CONFIG ioctl(2) failed")?;

        Ok(())
    }
}
