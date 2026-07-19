//! ldaphound-cli — command-line snapshot inspector.
//!
//! Usage:
//!   ldaphound-cli <dat-file>
//!   ldaphound-cli <dat-file> --object <index|dn|sid>
//!
//! Without --object it prints the header and a summary of every object.
//! With --object it dumps one object's attributes and its ACL breakdown.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use ldaphound_core::security::descriptor::SecurityDescriptor;
use ldaphound_core::snapshot::Snapshot;
use ldaphound_core::Sid;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: ldaphound-cli <dat-file> [--object <index|dn|sid>]");
        return ExitCode::from(2);
    }
    let path = PathBuf::from(&args[1]);
    let object_query = flag_value(&args, "--object");

    match run(&path, object_query.as_deref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter().skip(2);
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().cloned();
        }
    }
    None
}

fn run(path: &PathBuf, object_query: Option<&str>) -> ldaphound_core::ParseErrorResult<()> {
    let snap = Snapshot::parse_file(path)?;

    println!("Header:");
    println!("  server          : {}", snap.header.server);
    println!(
        "  filetime        : {} (unix={})",
        snap.header.filetime,
        snap.header.unix_timestamp().unwrap_or(0),
    );
    println!("  num_objects     : {}", snap.header.num_objects);
    println!("  num_properties  : {}", snap.properties.len());
    println!("  metadata_offset : 0x{:X}", snap.header.metadata_offset);
    println!("  treeview_offset : 0x{:X}", snap.header.treeview_offset);

    match object_query {
        Some(q) => {
            let idx = resolve_object(&snap, q);
            match idx {
                Some(i) => dump_object(&snap, i),
                None => {
                    eprintln!("object not found: {q}");
                    return Ok(());
                }
            }
        }
        None => {
            println!("\nObjects ({}):", snap.objects.len());
            for (i, obj) in snap.objects.iter().enumerate() {
                let classes = obj.object_classes();
                let primary = classes.last().map(|s| s.as_str()).unwrap_or("?");
                let sid = obj.object_sid().map(|s| s.to_string()).unwrap_or_default();
                let dn = obj.dn().unwrap_or("");
                println!("  [{i:>5}] {primary:<20} {dn}  {sid}");
            }
        }
    }
    Ok(())
}

fn resolve_object(snap: &Snapshot, q: &str) -> Option<usize> {
    if let Ok(i) = q.parse::<usize>() {
        return snap.objects.get(i).map(|_| i);
    }
    // By SID
    if let Ok(sid) = q.parse::<Sid>() {
        for (i, o) in snap.objects.iter().enumerate() {
            if o.object_sid().map(|s| s == sid).unwrap_or(false) {
                return Some(i);
            }
        }
    }
    // By DN (case-insensitive)
    let lower = q.to_ascii_lowercase();
    for (i, o) in snap.objects.iter().enumerate() {
        if o.dn().map(|d| d.eq_ignore_ascii_case(&lower)).unwrap_or(false) {
            return Some(i);
        }
    }
    None
}

fn dump_object(snap: &Snapshot, idx: usize) {
    let obj = &snap.objects[idx];
    let classes = obj.object_classes();
    println!("\nObject[{idx}]:");
    println!("  classes: [{}]", classes.join(", "));
    println!("  dn     : {}", obj.dn().unwrap_or(""));
    println!("  sid    : {}", obj.object_sid().map(|s| s.to_string()).unwrap_or_default());
    println!("  attrs  : {} entries", obj.attributes.len());

    // ACL breakdown
    if let Some(bytes) = obj.ntsd_bytes() {
        match SecurityDescriptor::from_bytes(bytes) {
            Ok(sd) => {
                println!(
                    "\n  nTSecurityDescriptor: {} bytes, rev={}, flags=0x{:04X}, dacl_protected={}",
                    bytes.len(),
                    sd.revision,
                    sd.control_flags,
                    sd.is_dacl_protected(),
                );
                println!("  owner: {}", sd.owner.as_ref().map(|s| s.to_string()).unwrap_or("-".into()));
                println!("  group: {}", sd.group.as_ref().map(|s| s.to_string()).unwrap_or("-".into()));
                if let Some(dacl) = &sd.dacl {
                    println!(
                        "\n  DACL: rev={}, {} ACEs",
                        dacl.revision, dacl.aces.len()
                    );
                    for (i, ace) in dacl.aces.iter().enumerate() {
                        let kind = match ace.ace_type() {
                            ldaphound_core::security::AceType::AccessAllowed => "Allow",
                            ldaphound_core::security::AceType::AccessDenied => "Deny",
                            ldaphound_core::security::AceType::AccessAllowedObject => "AllowObj",
                            ldaphound_core::security::AceType::AccessDeniedObject => "DenyObj",
                            _ => "Other",
                        };
                        let trustee = ace.trustee().map(|s| s.to_string()).unwrap_or("-".into());
                        let right = ace.right_name().unwrap_or("-".into());
                        let mask = ace.mask().map(|m| format!("{m}")).unwrap_or("-".into());
                        let inherited = if ace.is_inherited() { "inherited" } else { "explicit" };
                        println!("    ACE[{i:>2}] {kind:<8} {right:<45} mask={mask} trustee={trustee} [{inherited}]");
                    }
                }
            }
            Err(e) => println!("\n  nTSecurityDescriptor: parse failed: {e}"),
        }
    } else {
        println!("\n  (no nTSecurityDescriptor)");
    }
}
