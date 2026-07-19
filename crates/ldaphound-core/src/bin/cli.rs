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
//! Filtering:
//!   ldaphound-cli snapshot.dat --type user --type computer
//!   ldaphound-cli snapshot.dat --filter '(objectClass=computer)'
//!   ldaphound-cli snapshot.dat --filter '(&(objectCategory=Person)(objectClass=User))'
//!   ldaphound-cli snapshot.dat --filter '(sAMAccountName=j*)'
//!   ldaphound-cli snapshot.dat --type user --filter '(sAMAccountName=a*)'
//!
//! `--type` and `--filter` combine with AND. `--filter` accepts an LDAP
//! search filter (RFC 4515 §3 subset): `(&...)`, `(|...)`, `(!...)`,
//! `(attr=value)`, `(attr>=value)`, `(attr<=value)`, `(attr~=value)`,
//! `(attr=*)`, and `(attr=pre*mid*suf)` substring patterns.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ldaphound_core::filter::{Filter, LdapFilter, ObjectType};
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

    /// Filter objects by LDAP type. Repeatable to OR multiple types.
    /// Accepted values: user, group, computer, domain, ou, container, gpo, other.
    /// AND-combined with --filter.
    #[arg(long, value_name = "TYPE", value_parser = parse_object_type)]
    r#type: Vec<ObjectType>,

    /// LDAP search filter (RFC 4515 subset). Wrap in quotes on the shell.
    /// Examples: '(objectClass=computer)',
    /// '(&(objectCategory=Person)(objectClass=User))', '(sAMAccountName=j*)'.
    /// AND-combined with --type.
    #[arg(long, value_name = "FILTER")]
    filter: Option<String>,
}

/// Clap value_parser: friendly error on unknown type.
fn parse_object_type(s: &str) -> Result<ObjectType, String> {
    ObjectType::parse(s).ok_or_else(|| {
        format!("unknown type '{s}' (try: user, group, computer, domain, ou, container, gpo, other)")
    })
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
    let snap = Snapshot::parse_file(&cli.dat_file)?;

    // Header summary to stderr so stdout stays pipeable as pure LDAP data.
    eprintln!("# server          : {}", snap.header.server);
    eprintln!("# num_objects     : {}", snap.header.num_objects);
    eprintln!("# num_properties  : {}", snap.properties.len());
    eprintln!("# metadata_offset : 0x{:X}", snap.header.metadata_offset);

    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // --object bypasses the filter — dump one object's full ACL breakdown.
    if let Some(query) = &cli.object {
        match filter::resolve_object(&snap, query) {
            Some(i) => dump::dump_object_acl(&snap, i, &mut out)
                .map_err(ldaphound_core::ParseError::Io)?,
            None => eprintln!("# object not found: {query}"),
        }
        return Ok(());
    }

    // --type → coarse type allow-list (OR across repeats).
    let mut type_filter = Filter::new();
    for t in &cli.r#type {
        type_filter = type_filter.with_type(*t);
    }

    // --filter → LDAP search filter AST.
    let ldap = match cli.filter.as_deref() {
        Some(expr) => match LdapFilter::parse(expr) {
            Ok(f) => {
                eprintln!("# ldap filter: {expr}");
                Some(f)
            }
            Err(e) => {
                eprintln!("error: invalid --filter '{expr}': {e}");
                return Ok(());
            }
        },
        None => None,
    };
    if !type_filter.is_empty() {
        let names: Vec<&str> = cli.r#type.iter().map(|t| t.as_str()).collect();
        eprintln!("# type filter: [{}]", names.join(","));
    }

    let mut emitted = 0usize;
    let mut skipped = 0usize;
    for obj in &snap.objects {
        if !type_filter.matches(obj) {
            skipped += 1;
            continue;
        }
        if let Some(f) = &ldap {
            if !f.matches(obj) {
                skipped += 1;
                continue;
            }
        }
        dump::dump_object_ldap(obj, &mut out).map_err(ldaphound_core::ParseError::Io)?;
        emitted += 1;
    }
    eprintln!("# {emitted} object(s) emitted, {skipped} skipped");
    Ok(())
}
