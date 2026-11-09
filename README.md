# qnap-key-extract

Recover **LUKS encryption keys for QNAP QTS encrypted volumes** from:

- exported **`.key` files** (the 256-byte download from the QTS web UI),
- **DOM / config-flash dd images** (auto-unlock keys saved with "Save encryption key"),
- plain **passwords** (wrap them into the passphrase cryptsetup expects),
- the **factory default key** hardcoded in QTS.

Everything is implemented from scratch in pure Rust. The format knowledge was
reverse engineered from QTS 5.2 `libuLinux_Storage.so` (`Keyfile_to_Keystring`,
`decode_user_key`, `Volume_Generate_Encrypt_Key`, the ENCK/UKF flash helpers)
and validated **differentially against the genuine QNAP binaries** extracted
from the firmware (see *Validation* below).

## How QNAP volume encryption works

```
password typed in QTS UI (max 32 chars)
        │
        ▼
crypt(3) MD5 with fixed salt "$1$YCCaQNAP$"        ← Volume_Generate_Encrypt_Key
        │
        ▼
"$1$YCCaQNAP$<22 chars>"   (34 chars, this IS the LUKS passphrase)
        │
        ├──► passed to: cryptsetup luksOpen <dev> <name> --key-file=<tmp>
        └──► saved to DOM flash as  ENCK=<the 34-char hash>
```

So the LUKS passphrase is *never* the user's password; it is the md5-crypt
hash with the fixed salt `YCCaQNAP`:

```
openssl passwd -1 -salt YCCaQNAP 'YOUR_PASSWORD'
```

## Obtaining the `.key` file

**From the QTS web UI:**

1. Go to **Storage & Snapshots → Storage → Disks/VJBOD**
2. Select the encrypted volume
3. Click **Management → Export Encryption Key**
4. Save the downloaded `.key` file

The file is 256 bytes (or 512 for longer passwords). QTS 5.x may also export
a plain-text file containing the wrapped passphrase directly (both formats
are handled automatically by the `auto` subcommand).

**From a DOM / config-flash dump:**

If "Save encryption key" was checked when the volume was created, the
wrapped passphrase is embedded in a DOM partition or the config flash.
Dump it with:

```
dd if=/dev/sdaX of=dom.img bs=1M
```

Then scan with `qnap-key-extract dom dom.img`. The DOM is usually one of
`/dev/sda` through `/dev/sde` — often a small partition (< 64 MB) near the
end of the disk. On QTS 5, the relevant data is also mirrored to
`/etc/.sm_v2_storage_runtime_info` (an INI-like file readable without dd).

## The `.key` file format (`decode_user_key`)

The 256-byte `.key` files hide the **volume password** (the plaintext!) inside
random padding. Layout:

| offset         | content                                              |
|----------------|------------------------------------------------------|
| `0..8`         | random padding                                       |
| `8 + 9*i`      | key byte `i`, for `i` in `0..N` (stride **9**)       |
| everywhere else| random padding (why every export looks different)    |
| `248..250`     | ASCII decimal `N`, the key length (`01`..`28`)       |

Decoding is: `key[i] = file[8 + 9*i]` for `i < N`. A second entry point in QTS
(the CGI `keyStr` path) additionally subtracts the index: `key[i] -= i`; the
tool reports both variants when both are plausible. A 512-byte variant exists
(64 key bytes max, count field at offset 504, and the file must be **larger
than 512 bytes** — QTS truncates 257..512-byte files to 256).

The recovered password is then wrapped exactly like a UI-typed password:
`crypt(pw, "$1$YCCaQNAP$")` → LUKS passphrase.

QTS 5 also exports plain-text key files containing the raw 34-char wrapped
passphrase (and `storage_util --encrypt_pwd` output is sometimes saved as a
`.key` file, with an `Encrypted passwd is:` prefix). Both are handled.

## DOM auto-unlock keys (`ENCK=`)

When "Save encryption key" is checked, QTS writes `ENCK=<value>` to the DOM /
config flash (also mirrored to `/etc/.sm_v2_storage_runtime_info` under
`[Encryption] key_<volid>`). Values seen in the wild:

| value length | meaning                                                        |
|--------------|----------------------------------------------------------------|
| 34, starts `$1$YCCaQNAP$` | wrapped passphrase - use directly as LUKS passphrase |
| 32, `[a-z0-9]` | legacy backdoor key (CVE-2009-3200 era), stored with the first 8 chars reversed and appended to the end (deobfuscation included; 6-char variant offered too) |

The tool scans the whole image for `ENCK=` entries (offsets are printed) and
`UKF=` key-flag blocks (`K` = key saved on DOM, `M` = master-key mode).

## Usage

```
qnap-key-extract keyfile <file.key>   # decode a 256/512-byte .key blob
qnap-key-extract dom <image.dd>       # scan a DOM/config image for ENCK=
qnap-key-extract password <pw>        # wrap a password -> LUKS passphrase
qnap-key-extract default-key          # passphrase of the built-in default key
qnap-key-extract auto <path>          # auto-detect key file vs image
```

`-` reads stdin, e.g.:

```
dd if=/dev/sdx6 | qnap-key-extract dom -
```

### Unlocking a volume

Each reported candidate includes a ready LUKS passphrase:

```
# put the candidate passphrase in a file WITHOUT a trailing newline:
printf '%s' '$1$YCCaQNAP$fCKsRIY9UQxokLHp26tJO1' > /tmp/key
cryptsetup luksOpen /dev/mapper/cachedev1 myvol --key-file=/tmp/key
mount -t ext4 /dev/mapper/myvol /mnt
```

### The factory default key

QTS's encryption wizard has a "use default key" option. The password is
hardcoded in `libuLinux_Storage.so`:

```
QnapBenjamin2012  ->  $1$YCCaQNAP$z5eCw.l3Yw1I7H2P3pll2/
```

Try this first on any volume you cannot attribute a password to.

## Validation

- md5-crypt: byte-identical to `openssl passwd -1 -salt YCCaQNAP` and to the
  genuine `storage_util --encrypt_pwd` from the QTS 5.2 firmware
  (9/9 differential vectors incl. empty/unicode/60-char passwords).
- `.key` decode: byte-identical to the genuine `Keyfile_to_Keystring` called
  via dlopen on the firmware's `libuLinux_Storage.so`
  (10/10 differential vectors, 256- and 512-byte blobs).
- DOM scan: `ENCK=`/`UKF=` offsets, dedup, legacy deobfuscation verified by
  unit tests; legacy deobfuscation reproduces the CVE-2009-3200 example.

## Building

```
cargo build --release
# binary: target/release/qnap-key-extract
```

Differential test against a real firmware library (needs the QTS libs on
`LD_LIBRARY_PATH`):

```
QNAP_LIB=/path/to/libuLinux_Storage.so \
cargo run --release --example check_real
```
