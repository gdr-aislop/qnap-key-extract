use clap::{Parser, Subcommand};
use qnap_key_extract::{dom, keyfile, md5crypt};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

const QNAP_DEFAULT_PASSWORD: &str = "QnapBenjamin2012";

// ── ANSI helpers (zero dependencies) ──────────────────────────────────────

const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

fn e(label: &str, val: impl std::fmt::Display) -> String {
    format!("  {BOLD}{label}:{RESET} {val}")
}

fn heading(title: &str) -> String {
    let rule = "━".repeat(60);
    format!("\n{BOLD}{CYAN}{rule}{RESET}\n  {BOLD}{title}{RESET}\n{BOLD}{CYAN}{rule}{RESET}\n")
}

fn note(msg: &str) -> String {
    format!("  {DIM}└─ {msg}{RESET}")
}

fn warn(msg: impl std::fmt::Display) -> String {
    format!("  {YELLOW}{msg}{RESET}")
}

fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

fn print_cryptsetup_hint(passphrase: &str) {
    let quoted = sh_quote(passphrase);
    println!("{}", note(&format!(
        "cryptsetup luksOpen <device> <name> \\\n         --key-file <(printf '%s' {})",
        quoted
    )));
}

// ── CLI definition ────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "qnap-key-extract",
    version,
    about = "Recover LUKS passphrases from QNAP-encrypted volumes",
    long_about = "\
Recovers the LUKS passphrase of QNAP-encrypted volumes.

QNAP QTS never passes your volume password to LUKS directly — it wraps it
with md5-crypt using the fixed salt \"YCCaQNAP\". This tool reverses that
wrapping and recovers the actual LUKS passphrase from any of several
sources: exported .key files, DOM/config-flash images, or a plain password
typed in the QTS encryption wizard.",
    after_long_help = concat!(
        "\x1b[1mEXAMPLES\x1b[0m\n",
        "    # Decode a .key file downloaded from the QTS web UI\n",
        "    qnap-key-extract keyfile ./volume.key\n",
        "\n",
        "    # Scan a DD image of the DOM or config flash partition\n",
        "    qnap-key-extract dom /dev/sda\n",
        "\n",
        "    # Wrap a plain volume password into the LUKS passphrase\n",
        "    qnap-key-extract password \"my volume password\"\n",
        "\n",
        "    # Print the passphrase for factory-default encrypted volumes\n",
        "    qnap-key-extract default-key\n",
        "\n",
        "    # Auto-detect input type (.key vs DOM image)\n",
        "    qnap-key-extract auto backup.bin\n",
        "\n",
        "    # Read input from stdin\n",
        "    qnap-key-extract keyfile -\n",
        "    cat volume.key | qnap-key-extract keyfile -\n",
)
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Decode a QNAP .key file into the original volume password and LUKS passphrase
    #[command(visible_alias = "k")]
    Keyfile {
        /// Path to the .key file (use "-" for stdin)
        file: PathBuf,
    },
    /// Scan a DOM or config-flash image for saved encryption keys
    #[command(visible_alias = "d")]
    Dom {
        /// Path to a dd image of the DOM or config flash (use "-" for stdin)
        image: PathBuf,
    },
    /// Wrap a plaintext password into the LUKS passphrase used by QTS
    #[command(visible_alias = "p")]
    Password {
        /// The volume encryption password (as typed in the QTS wizard)
        password: String,
        /// Do not truncate to 32 characters (QTS UI limit)
        #[arg(long)]
        no_truncate: bool,
    },
    /// Print the LUKS passphrase derived from QTS's factory default key
    #[command(visible_alias = "def")]
    DefaultKey,
    /// Auto-detect whether input is a .key file or a DOM image and extract keys
    #[command(visible_alias = "a")]
    Auto {
        /// Path to a .key file or DOM image (use "-" for stdin)
        path: PathBuf,
    },
}

// ── Output helpers ────────────────────────────────────────────────────────

fn print_passphrase(label: &str, passphrase: &str) {
    println!("\n  {BOLD}{label}:{RESET}");
    println!("  {GREEN}{passphrase}{RESET}");
    print_cryptsetup_hint(passphrase);
}

fn report_keyfile(content: &[u8]) -> Result<(), String> {
    print!("{}", heading("QNAP .key file"));
    println!("{}", e("size", format!("{} bytes", content.len())));

    match keyfile::decode_keyfile(content) {
        Ok(candidates) => {
            println!("{}", e("format", format!("{} blob", candidates[0].format)));
            if candidates.len() > 1 {
                println!(
                    "{}",
                    warn("entry-point ambiguity — both decode variants look plausible; try \
                           them in the order shown below.")
                );
            }
            for (n, decoded) in candidates.iter().enumerate() {
                let pw = String::from_utf8_lossy(&decoded.key);
                let variant = if decoded.index_subtracted {
                    "index-subtracted (flag=1)"
                } else {
                    "plain (flag=0)"
                };
                println!("\n  {BOLD}candidate {} [{}]:{RESET}", n + 1, variant);
                println!("    password:       {pw}");
                if pw.is_empty() {
                    println!("    {DIM}(empty key string — nothing to wrap){RESET}");
                    continue;
                }
                let wrapped = md5crypt::qnap_wrap_password(&pw);
                println!("    LUKS passphrase: {GREEN}{wrapped}{RESET}");
                print_cryptsetup_hint(&wrapped);
            }
            Ok(())
        }
        Err(keyfile::DecodeError::BadLength(_)) => {
            match keyfile::decode_raw_string(content) {
                Some(keyfile::RawKeyString::WrappedPassphrase(hash)) => {
                    println!("{}", e("format", "plain text (QTS 5 exported key file)"));
                    println!("{}", e("content", "wrapped passphrase — use directly"));
                    println!();
                    print_passphrase("LUKS passphrase", &hash);
                    Ok(())
                }
                Some(keyfile::RawKeyString::PlainPassphrase(pw)) => {
                    println!("{}", e("format", "plain text"));
                    println!("{}", e("content", &pw));
                    let wrapped = md5crypt::qnap_wrap_password(&pw);
                    println!("{}", note("treating content as the volume password"));
                    println!();
                    print_passphrase("LUKS passphrase", &wrapped);
                    Ok(())
                }
                None => Err(
                    "not a QNAP .key blob (256/512 bytes) and not a plain-text key file"
                        .to_string(),
                ),
            }
        }
        Err(e) => Err(format!("failed to decode .key file: {e}")),
    }
}

fn report_dom(content: &[u8]) -> Result<(), String> {
    print!("{}", heading("QNAP DOM / config image scan"));
    println!("{}", e("size", format!("{} bytes", content.len())));

    let (entries, blocks) = dom::scan_dom(content);

    if !blocks.is_empty() {
        println!("\n  {BOLD}UKF= key-flag blocks{RESET}");
        for b in &blocks {
            let interesting: Vec<String> = b
                .flags
                .iter()
                .enumerate()
                .filter(|(_, &f)| f != 0 && f != 0xff)
                .map(|(i, &f)| {
                    format!(
                        "vol_{} = {}",
                        i,
                        if (0x20..=0x7e).contains(&f) {
                            format!("'{}'", f as char)
                        } else {
                            format!("0x{:02x}", f)
                        }
                    )
                })
                .collect();
            let desc = if interesting.is_empty() {
                DIM.to_string() + "(none set)" + RESET
            } else {
                interesting.join(", ")
            };
            println!("    @ 0x{:08x}:  {}", b.offset, desc);
        }
    }

    if entries.is_empty() {
        return Err("no ENCK= entries found in the image".into());
    }

    println!(
        "\n  {BOLD}ENCK= entries found:{RESET} {}{}",
        entries.len(),
        if entries.len() == 1 {
            ""
        } else {
            " (only the first occurrence of each unique value is shown)"
        }
    );

    for (n, e) in entries.iter().enumerate() {
        let kind_label = match e.kind {
            dom::EnckKind::ModernWrapped => "modern wrapped passphrase",
            dom::EnckKind::LegacyBackdoor => "legacy 32-char backdoor key",
            dom::EnckKind::Unknown => "unrecognised format",
        };
        println!(
            "\n  {BOLD}[{}] @ 0x{:08x}{RESET}  {kind_label}",
            n + 1,
            e.offset
        );
        println!("    raw: {DIM}{}{RESET}", &e.raw);

        for (ci, c) in e.candidates.iter().enumerate() {
            println!("\n    {BOLD}option {}:{RESET}  {}", ci + 1, c.description);
            println!("      key:             {YELLOW}{}{RESET}", c.key);
            if let Some(p) = &c.luks_passphrase {
                println!("      LUKS passphrase:  {GREEN}{p}{RESET}");
                print_cryptsetup_hint(p);
            }
        }
    }

    let hint_note = if entries.len() == 1 {
        "the candidate above"
    } else {
        "candidates in order from the first ENCK= entry"
    };
    println!(
        "\n  {BOLD}hint:{RESET} try {} with:",
        hint_note
    );
    println!("        cryptsetup luksOpen <device> <name> --key-file <(printf '%s' '<candidate key>')");
    println!("  {DIM}  (the --key-file must contain the candidate key with no trailing newline){RESET}");
    Ok(())
}

// ── Partition table helpers ───────────────────────────────────────────────

struct Partition {
    start: u64,
    end: u64,
    label: String,
}

fn probe_partitions(img: &[u8]) -> Vec<Partition> {
    let mut out: Vec<Partition> = Vec::new();

    // GPT check: header signature "EFI PART" at LBA 1 (byte 512)
    if img.len() >= 512 + 8 && &img[512..520] == b"EFI PART" {
        // Parse GPT partition entries
        let sector = 512u64;
        let header = &img[512..];
        let entry_lba = u64::from_le_bytes(header[72..80].try_into().unwrap()) * sector;
        let num_entries = u32::from_le_bytes(header[80..84].try_into().unwrap());
        let entry_size = u32::from_le_bytes(header[84..88].try_into().unwrap());
        for i in 0..num_entries {
            let off = (entry_lba + i as u64 * entry_size as u64) as usize;
            if off + 128 > img.len() {
                break;
            }
            let entry = &img[off..off + 128];
            let type_guid = &entry[0..16];
            if type_guid == [0u8; 16] {
                continue;
            }
            let start = u64::from_le_bytes(entry[32..40].try_into().unwrap());
            let end = u64::from_le_bytes(entry[40..48].try_into().unwrap());
            let name = String::from_utf16_lossy(
                entry[56..128]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            let label = if name.is_empty() {
                format!("GPT partition {}", i + 1)
            } else {
                format!("GPT partition {} ({})", i + 1, name.trim())
            };
            out.push(Partition {

                start,
                end,
                label,
            });
        }
        return out;
    }

    // MBR check: signature 0x55AA at offset 0x1FE
    if img.len() >= 512 && img[510] == 0x55 && img[511] == 0xAA {
        let mbr_type = img[450]; // offset 0x1C2 = partition 2 type (indicates GPT protective)
        if mbr_type == 0xEE {
            return out;
        }
        for i in 0..4 {
            let off = 446 + i * 16;
            if off + 16 > img.len() {
                break;
            }
            let status = img[off];
            let type_id = img[off + 4];
            if type_id == 0 || type_id == 0xEE {
                continue;
            }
            let lba = u32::from_le_bytes(img[off + 8..off + 12].try_into().unwrap()) as u64;
            let sectors =
                u32::from_le_bytes(img[off + 12..off + 16].try_into().unwrap()) as u64;
            let kind = match type_id {
                0x83 => "Linux",
                0x82 => "swap",
                0x0C | 0x0B => "FAT32",
                0x07 => "NTFS/exFAT",
                0xDA => "data",
                0x06 => "FAT16",
                0x05 | 0x0F | 0x85 => "extended",
                _ => "unknown",
            };
            let boot = if (status & 0x80) != 0 { " (bootable)" } else { "" };
            out.push(Partition {

                start: lba * 512,
                end: (lba + sectors) * 512,
                label: format!("MBR partition {}{} ({}, type 0x{:02X})", i + 1, boot, kind, type_id),
            });
        }
        return out;
    }

    out
}

fn scan_partitions(img: &[u8]) -> Result<(), String> {
    let parts = probe_partitions(img);
    let mut found_any = false;

    if parts.is_empty() {
        return report_dom(img);
    }

    println!(
        "\n  {BOLD}partition table detected — scanning each partition:{RESET}"
    );
    for p in &parts {
        let start = p.start as usize;
        let end = (p.end as usize).min(img.len());
        if start > end || start >= img.len() {
            println!(
                "  {DIM}  {} — outside image, skipping{RESET}",
                p.label
            );
            continue;
        }
        let slice = &img[start..end];
        let (entries, blocks) = dom::scan_dom(slice);
        if entries.is_empty() && blocks.is_empty() {
            continue;
        }
        if !found_any {
            found_any = true;
        }
        println!(
            "\n  {BOLD}{}{RESET}  @ LBA {} ({})",
            p.label, p.start / 512, &format_bytes(p.end - p.start)
        );
        if !blocks.is_empty() {
            println!("    {} UKF= block(s)", blocks.len());
        }
        println!("    {} ENCK= entry(s)", entries.len());
        for e in &entries {
            let kind_label = match e.kind {
                dom::EnckKind::ModernWrapped => "modern wrapped",
                dom::EnckKind::LegacyBackdoor => "legacy 32-char",
                dom::EnckKind::Unknown => "unknown",
            };
            println!("    @ +0x{:06x}: {}  {}", e.offset, kind_label, e.raw);
            for c in &e.candidates {
                println!("      key: {YELLOW}{}{RESET}", c.key);
                if let Some(p) = &c.luks_passphrase {
                    println!("      LUKS passphrase: {GREEN}{p}{RESET}");
                    print_cryptsetup_hint(p);
                }
            }
        }
    }

    if !found_any {
        // Fallback: scan the whole image
        println!("  no DOM data found in any partition, falling back to full-image scan");
        return report_dom(img);
    }
    Ok(())
}

fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = n as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.1} {}", size, UNITS[unit])
}

// ── File I/O ──────────────────────────────────────────────────────────────

fn read_file(path: &PathBuf) -> Result<Vec<u8>, String> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        return Ok(buf);
    }
    let meta = fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    let expected = meta.len() as usize;
    let mut f = fs::File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut buf = Vec::with_capacity(expected.min(64 * 1024 * 1024));
    f.read_to_end(&mut buf)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok(buf)
}

fn looks_like_keyfile(content: &[u8]) -> bool {
    content.len() <= 512
}

// ── Commands ──────────────────────────────────────────────────────────────

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Keyfile { file } => {
            let content = read_file(&file)?;
            report_keyfile(&content)
        }
        Command::Dom { image } => {
            let content = read_file(&image)?;
            scan_partitions(&content)
        }
        Command::Password {
            password,
            no_truncate,
        } => {
            let orig_len = password.len();
            let pw: String = if no_truncate || orig_len <= 32 {
                password
            } else {
                eprintln!(
                    "{}",
                    warn("password truncated to 32 characters (QTS UI limit); \
                          use --no-truncate to keep the full value")
                );
                password.chars().take(32).collect()
            };
            print!("{}", heading("QNAP password wrapping"));
            println!("{}", e("password", &pw));
            if !no_truncate && orig_len > 32 {
                println!(
                    "{}",
                    DIM.to_string()
                        + "  (original was "
                        + &orig_len.to_string()
                        + " chars — truncated to 32)"
                        + RESET
                );
            }
            let wrapped = md5crypt::qnap_wrap_password(&pw);
            println!();
            print_passphrase("LUKS passphrase", &wrapped);
            Ok(())
        }
        Command::DefaultKey => {
            print!("{}", heading("QNAP factory default key"));
            println!("{}", e("default password", QNAP_DEFAULT_PASSWORD));
            println!(
                "{}",
                note("used by QTS when \"use default key\" is selected in the wizard")
            );
            let wrapped = md5crypt::qnap_wrap_password(QNAP_DEFAULT_PASSWORD);
            println!();
            print_passphrase("LUKS passphrase", &wrapped);
            Ok(())
        }
        Command::Auto { path } => {
            let content = read_file(&path)?;
            if looks_like_keyfile(&content) {
                report_keyfile(&content)
            } else {
                scan_partitions(&content)
            }
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\n{}", format!("  {BOLD}error:{RESET} {e}"));
            ExitCode::FAILURE
        }
    }
}
