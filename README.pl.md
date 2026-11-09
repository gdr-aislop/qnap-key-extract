# qnap-key-extract

Odzyskaj **klucze szyfrowania LUKS dla zaszyfrowanych woluminów QNAP QTS** z:

- wyeksportowanych **plików `.key`** (256-bajtowe pliki pobrane z interfejsu WWW QTS),
- **obrazów DOM / config-flash** (klucze automatycznego odblokowania zapisane opcją „Save encryption key"),
- zwykłych **haseł** (konwersja na hasło LUKS, którego oczekuje cryptsetup),
- **fabrycznego klucza domyślnego** na stałe wbudowanego w QTS.

## Użycie

```
qnap-key-extract keyfile <plik.key>   # dekoduj 256/512-bajtowy plik .key
qnap-key-extract dom <obraz.dd>       # skanuj obraz DOM w poszukiwaniu ENCK=
qnap-key-extract password <haslo>     # konwertuj hasło na hasło LUKS
qnap-key-extract default-key          # hasło LUKS dla fabrycznego klucza
qnap-key-extract auto <sciezka>       # auto-detekcja pliku klucza vs obrazu
```

`-` czyta ze standardowego wejścia, np.:

```
dd if=/dev/sdx6 | qnap-key-extract dom -
```

## Uzyskanie pliku `.key`

### Z interfejsu WWW QTS

1. Przejdź do **Storage & Snapshots → Storage → Disks/VJBOD**
2. Wybierz zaszyfrowany wolumin
3. Kliknij **Management → Export Encryption Key**
4. Zapisz pobrany plik `.key`

Plik ma 256 bajtów (lub 512 dla dłuższych haseł). QTS 5.x może również
wyeksportować plik tekstowy zawierający bezpośrednio gotowe hasło LUKS
(oba formaty są obsługiwane automatycznie przez podkomendę `auto`).

### Zrzut partycji DOM / config-flash

Jeśli przy tworzeniu woluminu zaznaczono „Save encryption key", hasło LUKS
jest zapisane w partycji DOM lub config flash. Wykonaj zrzut poleceniem:

```
dd if=/dev/sdX of=dom.img bs=1M
```

Następnie przeskanuj: `qnap-key-extract dom dom.img`. Partycja DOM to zwykle
jedna z `/dev/sda`–`/dev/sde` — często mały obszar (< 64 MB) w pobliżu końca
dysku. W QTS 5 istotne dane są również zdublowane do
`/etc/.sm_v2_storage_runtime_info` (plik w formacie INI, czytelny bez dd).

### Odblokowanie woluminu

Każdy znaleziony kandydat zawiera gotowe hasło LUKS:

```
# zapisz hasło kandydata w pliku BEZ znaku nowej linii:
printf '%s' '$1$YCCaQNAP$fCKsRIY9UQxokLHp26tJO1' > /tmp/key
cryptsetup luksOpen /dev/mapper/cachedev1 myvol --key-file=/tmp/key
mount -t ext4 /dev/mapper/myvol /mnt
```

### Fabryczny klucz domyślny

Kreator szyfrowania QTS ma opcję „use default key". Hasło jest na stałe
wbudowane w `libuLinux_Storage.so`:

```
QnapBenjamin2012  ->  $1$YCCaQNAP$z5eCw.l3Yw1I7H2P3pll2/
```

Wypróbuj to najpierw na każdym woluminie, do którego nie znasz hasła.

## Jak działa szyfrowanie woluminów QNAP

```
hasło wpisane w interfejsie QTS (max 32 znaki)
         │
         ▼
crypt(3) MD5 ze stałą solą "$1$YCCaQNAP$"        ← Volume_Generate_Encrypt_Key
         │
         ▼
"$1$YCCaQNAP$<22 znaki>"   (34 znaki — TO JEST hasło LUKS)
         │
         ├──► przekazane do: cryptsetup luksOpen <urz> <nazwa> --key-file=<tmp>
         └──► zapisane do flash DOM jako  ENCK=<34-znakowy hash>
```

Zatem hasło LUKS *nigdy* nie jest hasłem użytkownika; jest to skrót md5-crypt
ze stałą solą `YCCaQNAP`:

```
openssl passwd -1 -salt YCCaQNAP 'TWOJE_HASLO'
```

## Format pliku `.key` (`decode_user_key`)

256-bajtowe pliki `.key` ukrywają **hasło woluminu** (jawnym tekstem!) wśród
losowego wypełnienia. Układ:

| offset        | zawartość                                           |
|---------------|-----------------------------------------------------|
| `0..8`        | losowe wypełnienie                                  |
| `8 + 9*i`     | bajt klucza `i`, dla `i` w `0..N` (krok **9**)      |
| reszta        | losowe wypełnienie (dlatego każdy eksport wygląda inaczej) |
| `248..250`    | ASCII dziesiętne `N`, długość klucza (`01`–`28`)    |

Dekodowanie: `key[i] = file[8 + 9*i]` dla `i < N`. Drugi punkt wejścia w QTS
(ścieżka CGI `keyStr`) dodatkowo odejmuje indeks: `key[i] -= i`; narzędzie
raportuje oba warianty, gdy oba są prawdopodobne. Istnieje też wariant
512-bajtowy (maks. 64 bajty klucza, pole licznika na offsecie 504, a plik
musi być **większy niż 512 bajtów** — QTS obcina pliki 257–512 bajtów do 256).

Odzyskane hasło jest następnie zawijane dokładnie jak hasło wpisane w UI:
`crypt(pw, "$1$YCCaQNAP$")` → hasło LUKS.

QTS 5 eksportuje również tekstowe pliki klucza zawierające surowy 34-znakowy
skrót (a wyjście `storage_util --encrypt_pwd` bywa zapisywane jako plik `.key`
z prefiksem `Encrypted passwd is:`). Oba przypadki są obsługiwane.

## Klucze DOM auto-unlock (`ENCK=`)

Gdy zaznaczono „Save encryption key", QTS zapisuje `ENCK=<wartość>` do pamięci
flash DOM / config flash (oraz do `/etc/.sm_v2_storage_runtime_info` w sekcji
`[Encryption] key_<id_woluminu>`). Spotykane wartości:

| długość wart. | znaczenie                                                      |
|---------------|----------------------------------------------------------------|
| 34, zaczyna się `$1$YCCaQNAP$` | gotowe hasło LUKS — użyj bezpośrednio              |
| 32, `[a-z0-9]` | stary klucz zapasowy (era CVE-2009-3200), przechowywany z pierwszymi 8 znakami odwróconymi i doklejonymi na koniec (deobfuskacja w zestawie; oferowany też wariant 6-znakowy) |

Narzędzie skanuje cały obraz w poszukiwaniu wpisów `ENCK=` (wyświetlane są
offsety) oraz bloków flag `UKF=` (`K` = klucz zapisany na DOM, `M` = tryb
klucza głównego).

## Walidacja

- md5-crypt: identyczny bajt po bajcie z `openssl passwd -1 -salt YCCaQNAP`
  i z oryginalnym `storage_util --encrypt_pwd` z firmware QTS 5.2
  (9/9 wektorów różnicowych, w tym puste/unicode/60-znakowe hasła).
- dekodowanie `.key`: identyczne bajt po bajcie z oryginalnym
  `Keyfile_to_Keystring` wywołanym przez dlopen z firmware'owego
  `libuLinux_Storage.so` (10/10 wektorów różnicowych, bloby 256 i 512 bajtów).
- skanowanie DOM: offsety `ENCK=`/`UKF=`, deduplikacja, deobfuskacja starych
  kluczy zweryfikowane testami jednostkowymi; deobfuskacja odtwarza przykład
  z CVE-2009-3200.

## Budowanie

```
cargo build --release
# binarka: target/release/qnap-key-extract
```

Test różnicowy z prawdziwą biblioteką firmware'ową (wymaga bibliotek QTS
na `LD_LIBRARY_PATH`):

```
QNAP_LIB=/ścieżka/do/libuLinux_Storage.so \
cargo run --release --example check_real
```
