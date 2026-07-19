//! ldaphound-cli — command-line snapshot inspector.
//!
//! Parses an ADExplorer `.dat` snapshot and dumps objects in `ldapsearch`
//! style (`dn: ...` + one `attribute: value` line per attribute, blank line
//! between objects). Output and filtering helpers live in
//! `ldaphound_core::{dump, filter}` so the GUI and tests can reuse them.
//!
//! Examples:
//!   ldaphound-cli snapshot.dat
//!   ldaphound-cli snapshot.dat --object "CN=Administrator,CN=Users,DC=x"
//!   ldaphound-cli snapshot.dat --object 42
//!   ldaphound-cli snapshot.dat --object S-1-5-21-...-519
//!
//! Reserved (parsed but not yet applied — see `filter` module):
//!   --type user --type computer   # filter by LDAP object type
//!   --filter admin                # substring on DN / name

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ldaphound_core::{dump, filter, Snapshot};

#[derive(Parser, Debug)]
#[command(
    name = "ldaphound-cli",
    version,
    about = "Inspect an ADExplorer .dat snapshot (ldapsearch-style dump + ACL breakdown)"
)]
struct Cli {
    /// Path to the .dat snapshot file exported by ADExplorer.
    dat_file: PathBuf,

    /// Dump a single object (by index, DN, or SID) with its full ACL
    /// breakdown instead of listing all objects.
    #[arg(long, value_name = "INDEX|DN|SID")]
    object: Option<String>,

    /// TODO: filter objects by LDAP type. Repeatable to OR multiple types.
    /// Accepted values (once implemented): user, group, computer, domain,
    /// ou, container, gpo. Currently parsed but not applied.
    #[arg(long, value_name = "TYPE")]
    r#type: Vec<String>,

    /// TODO: substring filter on DN / name (case-insensitive). Currently
    /// parsed but not applied.
    #[arg(long, value_name = "SUBSTR")]
    filter: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> ldaphound_core::ParseErrorResult<()> {
    // Reserved flags — acknowledge on stderr so stdout stays pure LDAP data.
    if !cli.r#type.is_empty() {
        eprintln!(
            "# warning: --type {:?} not yet implemented; emitting all object types",
            cli.r#type
        );
    }
    if let Some(f) = &cli.filter {
        eprintln!("# warning: --filter {f:?} not yet implemented; emitting all objects");
    }

    let snap = Snapshot::parse_file(&cli.dat_file)?;

    // Header summary to stderr so stdout stays pipeable as pure LDAP data.
    eprintln!("# server          : {}", snap.header.server);
    eprintln!("# num_objects     : {}", snap.header.num_objects);
    eprintln!("# num_properties  : {}", snap.properties.len());
    eprintln!("# metadata_offset : 0x{:X}", snap.header.metadata_offset);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    if let Some(query) = &cli.object {
        match filter::resolve_object(&snap, query) {
            Some(i) => dump::dump_object_acl(&snap, i, &mut out)
                .map_err(|e| ldaphound_core::ParseError::Io(e))?,
            None => eprintln!("# object not found: {query}"),
        }
        return Ok(());
    }

    let mut emitted = 0usize;
    for obj in &snap.objects {
        dump::dump_object_ldap(obj, &mut out).map_err(|e| ldaphound_core::ParseError::Io(e))?;
        emitted += 1;
    }
    eprintln!("# {emitted} object(s) emitted");
    Ok(())
}
