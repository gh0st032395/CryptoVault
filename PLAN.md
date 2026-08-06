# CryptoVault — Piano di sviluppo

> Versione 1.0 — 6 agosto 2026. Tutte le decisioni fondamentali sono prese.
> Documento vivo: `docs/ADR/` registrerà ogni futura variazione con la sua motivazione.

---

## 1. Cos'è CryptoVault

Un'applicazione desktop che crea **aree cifrate persistenti (vault)** dentro le quali i file si
usano, non solo si archiviano. L'utente sblocca un vault con una password, naviga i suoi file,
li apre, li modifica, li richiude — e sul disco non esiste nulla in chiaro se non per la durata
esplicita di una sessione di lavoro tracciata.

Privacy by design, come Cryptera: nessun cloud proprietario, nessuna telemetria, nessuna
connessione di rete se non l'updater firmato su richiesta esplicita.

### Differenza sostanziale rispetto a Cryptera

Cryptera è un **trasformatore one-shot**: file in chiaro → `.ecf` → file in chiaro. Il file viene
letto, cifrato e scritto per intero.

CryptoVault è uno **storage cifrato mutabile**: accesso casuale in lettura, scrittura
incrementale, gerarchia di directory, rinomina, metadati, e uno stato aperto/chiuso del vault.
Requisiti che il formato `.ecf` non può soddisfare — un `.ecf` va decifrato tutto per leggerne 4 KB.

Riusiamo le **primitive** e la **disciplina** di Cryptera (Argon2id, AES-256-GCM, `zeroize`,
gestione errori, `ControlFlags` per pausa/annullamento, Reed-Solomon, rigore su test e fuzzing).
Riprogettiamo il **formato**, che è un problema diverso.

---

## 2. Decisioni prese

### Prodotto

| Ambito | Decisione |
|---|---|
| Licenza | Open source, **MIT OR Apache-2.0** (come Cryptera) |
| Utente target | **Entrambi**: default forti e semplici, sezione avanzata a richiesta |
| Piattaforme | **Windows, macOS, Linux**. Nessun mobile |
| Lingue | **Italiano + Inglese** dalla v1 |
| CLI | Strumento interno in M2, **prodotto pubblico dopo il rilascio** |
| Aggiornamenti | **Updater firmato, manuale**, unica connessione di rete |
| Primo traguardo | **Un vault che uso io** (fine M4), rilascio pubblico dopo |

### Architettura e formato

| Ambito | Decisione |
|---|---|
| Modello d'uso | **Ibrido**: browser interno + app esterne in v1, disco virtuale montato in M14. Astrazione VFS fin dal primo giorno |
| Storage | **Directory con file cifrati singolarmente**, nomi e struttura cartelle cifrati |
| Sync cloud | **Caso d'uso di primo livello** (Dropbox, iCloud, Drive, OneDrive) |
| Sblocco | **Password (Argon2id)** in v1; recovery key, biometria e hardware key già previsti nel formato via **key slot** |
| Riuso Cryptera | **Copia del core crypto** nel nuovo repo, adattato al modello a chunk |
| Compressione | **Nessuna sui file normali**; solo come azione manuale di *archiviazione* su file a riposo |
| Metadati conservati | Date di modifica e creazione, permessi POSIX e flag di eseguibilità, tag e note dell'utente. **No** xattr/tag di sistema |
| Scala di progetto | **Caso generale**: streaming ovunque, UI virtualizzata, indice persistente, benchmark in CI |

### Comportamento

| Ambito | Decisione |
|---|---|
| Versioning | **Opt-in per singolo file**: l'utente marca i file da versionare |
| Auto-lock | **Politica scelta dall'utente** fra tre; default: avviso con countdown di 60 s, poi blocco forzato |
| Uscita dati in chiaro | **Policy scelta alla creazione del vault**: *normale* (uscita libera) o *sigillato* (solo viewer interni ed export cifrato) |
| Anteprime | **Disattivate di default**; attivabili **per cartella**, previa **riautenticazione** |
| Viewer interni | Immagini e testo in Rust puro; **PDF in processo isolato** senza accesso alle chiavi |
| Audit log | **Cifrato e locale per macchina**, fuori dalla cartella sincronizzata |
| Backup | **Funzione integrata** su cartella/disco esterno **+ export in archivio unico** `.cvarchive` |
| Integrazione OS | Tray/barra dei menu, **menu contestuale Finder/Explorer**, associazione file e **hotkey globale di blocco**. Nessun avvio automatico al login |
| Negabilità plausibile | **Rimandata**, tema tenuto aperto: i key slot la rendono aggiungibile senza cambi di formato |

### Lignaggio del design

Il formato scelto (per-file, nomi cifrati, directory mappate su ID) è sostanzialmente quello di
**Cryptomator**, ed è una scelta deliberata: è l'unico design che soddisfa insieme
"sincronizzabile su cloud", "accesso casuale" e "struttura nascosta", ed è passato per audit
pubblici. Non copiamo codice e non puntiamo alla compatibilità di formato, ma partiamo dalle sue
lezioni invece di reinventarle sbagliando.

---

## 3. Architettura

```
CryptoVault/
├── crates/
│   ├── cv-crypto/      Primitive: KDF, AEAD, HKDF, AES-SIV, key slot, zeroize
│   ├── cv-format/      Formato su disco: config, header, chunk, nomi, metadati
│   ├── cv-vault/       Logica vault: unlock/lock, mapping directory, CRUD
│   ├── cv-vfs/         Astrazione filesystem (trait VaultFs) — ponte verso il mount
│   ├── cv-ops/         Job: import/export, sessioni esterne, watcher, search, backup
│   ├── cv-render/      Binario separato e sandboxed: rendering PDF e decodifica immagini
│   └── cv-cli/         CLI headless
├── src-tauri/          Backend Tauri: comandi, stato, auto-lock, tray, updater
├── native/
│   ├── macos-finder/   Finder Sync Extension (Swift)
│   └── windows-shell/  Shell extension per il menu contestuale (Rust/C++)
├── ui/                 Frontend Svelte + TypeScript + Vite
├── docs/
│   ├── FORMAT_SPEC.md  Specifica normativa del formato, versionata
│   ├── THREAT_MODEL.md Modello di minaccia e limiti dichiarati
│   └── ADR/            Decision record
├── tests/              Integrazione, vettori congelati, compatibilità, benchmark di scala
└── fuzz/               Fuzzing: header, chunk, nomi, metadati, path traversal
```

Le dipendenze vanno solo verso il basso:
`ui → src-tauri → cv-ops → cv-vfs → cv-vault → cv-format → cv-crypto`.
`cv-cli` sta allo stesso livello di `src-tauri`. **Nessun crate sotto `cv-ops` conosce Tauri**,
altrimenti la CLI e il futuro mount diventano impossibili.

`cv-render` è un processo separato per costruzione: non ha accesso alla memoria delle chiavi,
riceve byte già decifrati su pipe e restituisce pixel.

### 3.1 Gerarchia delle chiavi

La decisione più importante del progetto: se sbagliata, aggiungere biometria o recovery key
costringerebbe a ri-cifrare i vault esistenti.

```
password ──Argon2id(salt, params)──> KEK (32 B, mai persistita)
                                      │
                     MasterSeed (32 B, casuale, generato alla creazione)
                                      │
          ┌──────────┬────────────────┼─────────────┬──────────────┐
     HKDF "content" "names"        "mac"        "audit"        "meta"
          │          │               │              │              │
      K_content   K_names         K_mac        K_audit       K_meta
    (chiavi file) (AES-SIV)   (HMAC dirId,   (log locale)  (indice, cache)
                               MAC config)
```

Il `MasterSeed` è l'unico segreto che conta. Vive **avvolto** dentro `vault.cvconf`, in una
struttura a **key slot**:

| Slot | Metodo di sblocco | Contenuto | Fase |
|---|---|---|---|
| 0 | Password | `AEAD(KEK_password, MasterSeed)` | **v1** |
| 1 | Recovery key (24 parole) | `AEAD(KEK_recovery, MasterSeed)` | formato in v1, UI in M11 |
| 2 | Keychain OS / biometria | `AEAD(KEK_os, MasterSeed)` | M11 |
| 3 | Keyfile / FIDO2 hmac-secret | `AEAD(KEK_hw, MasterSeed)` | M12 |
| 4+ | Duress / vault nascosto | avvolge un MasterSeed **diverso** | M13, da valutare |

Ogni slot avvolge lo stesso MasterSeed in modo indipendente. Aggiungere Touch ID fra sei mesi
significa scrivere un blocco da 60 byte: **zero re-encryption dei dati**. Cambiare password idem.
È per questo che gli slot entrano nel formato v1 anche se l'interfaccia arriva molto dopo.

`vault.cvconf` è autenticato per intero con `K_mac`. Impedisce a chi ha accesso al disco di
abbassare i parametri Argon2id, cambiare l'algoritmo AEAD o disattivare la modalità sigillata
(downgrade attack): lo sblocco fallirebbe.

**Parametri Argon2id di default:** `m=256 MiB, t=3, p=4`, con calibrazione automatica alla
creazione (target ~1 s sulla macchina corrente, mai sotto un minimo prudenziale). I parametri
sono scritti nel config, quindi un vault creato su una macchina potente resta apribile su una
debole, solo più lentamente.

### 3.2 Formato dei contenuti

```
FILE CIFRATO (.cvf) — modalità LIVE
┌────────────────────────────────────────────────────────────────┐
│ HEADER (variabile)                                             │
│   magic "CVF1"(4) │ ver(1) │ alg_id(1) │ mode(1) │ risv(1)     │
│   fileId (16, casuale, IMMUTABILE, in chiaro ma autenticato)   │
│   nonce_hdr (12) │ meta_len (u32)                              │
│   AEAD(K_content, nonce_hdr, fileKey ‖ plainSize ‖ metadata)   │
│   + tag (16)                                                    │
├────────────────────────────────────────────────────────────────┤
│ CHUNK 0 : nonce(12) │ ciphertext(≤32 KiB) │ tag(16)            │
│ CHUNK 1 : nonce(12) │ ciphertext(≤32 KiB) │ tag(16)            │
│ ...                                                             │
└────────────────────────────────────────────────────────────────┘
AAD di ogni chunk = chunk_index (u64 BE) ‖ fileId
```

Le ragioni dietro ogni scelta:

- **Chunk da 32 KiB → accesso casuale.** Il chunk che contiene l'offset `o` è `o / 32768`.
  Leggere 4 KB da un file di 2 GB costa una decifratura di 32 KiB, non di 2 GB.
- **`fileKey` distinta per ogni file.** Limita il raggio di ogni chiave e rende la cancellazione
  crittografica implicita: eliminare il file distrugge l'unica copia della sua chiave, quindi il
  ciphertext eventualmente recuperabile dal disco resta inutile per sempre.
- **`fileId` nell'AAD, non il nonce dell'header.** Punto sottile ma decisivo: i metadati sono
  modificabili (aggiungere un tag, marcare il file come versionato), e ogni modifica ri-sigilla
  l'header con un nuovo nonce. Se i chunk fossero legati al nonce dell'header, aggiungere un tag
  invaliderebbe l'intero file. Il `fileId` è casuale, immutabile e generato alla creazione.
- **`chunk_index` nell'AAD.** Impedisce di riordinare, duplicare o rimuovere chunk.
- **`plainSize` autenticato.** Rileva il troncamento, che l'AEAD da solo non vede.
- **Nonce casuale a ogni scrittura di chunk, mai derivato dall'indice.** Con GCM, riusare la
  coppia (chiave, nonce) su contenuto diverso rivela la chiave di autenticazione. I file sono
  mutabili e un chunk può essere riscritto migliaia di volte: un nonce = indice sarebbe una
  bomba a orologeria silenziosa.
- **Overhead:** 28 B ogni 32 KiB = **0,085%**, più l'header.

**AEAD di default: AES-256-GCM** — AES-NI è presente su tutti i target desktop ed è ciò che
Cryptera già usa e testa. Il campo `alg_id` garantisce agilità: `0x02` = XChaCha20-Poly1305,
implementato in M1 anche se non esposto in UI.

#### Le due modalità di un file

| Modalità | `mode` | Struttura | Uso |
|---|---|---|---|
| **LIVE** | `0x01` | Chunk non compressi, accesso casuale, scrittura in-place | Predefinita, ogni file |
| **ARCHIVED** | `0x02` | Stream compresso (zstd/LZMA2) + parità Reed-Solomon opzionale, sola lettura sequenziale | Azione manuale "Archivia" su file a riposo |

L'archiviazione unifica in un unico concetto le due funzioni che non possono convivere con la
mutabilità: la **compressione** (romperebbe la mappatura offset→chunk) e la **parità
Reed-Solomon** (andrebbe ricalcolata a ogni scrittura). Un file archiviato è leggibile ed
esportabile; per modificarlo l'utente lo riporta a LIVE con un'azione esplicita. Il codice
GF(256) di Cryptera si riusa quasi invariato.

#### Metadati cifrati

Nel blocco `metadata` autenticato dell'header, serializzati in formato compatto ed estensibile
(CBOR, campi sconosciuti ignorati per compatibilità in avanti):

```
mtime, ctime            date originali, ripristinate all'export
mode_posix, executable  permessi normalizzati fra i tre OS
versioned: bool         se questo file va versionato  ← scelta per singolo file
tags: [string]          etichette dell'utente
note: string            annotazione libera
original_ext: string    estensione originale, per l'icona senza decifrare il contenuto
```

I metadati delle directory (incluso `previews_enabled`) vivono nel file `.cvd` della directory,
con la stessa struttura.

### 3.3 Nomi e struttura delle directory

Ogni directory ha un `dirId` casuale (UUID v4). Sul disco vive in un albero piatto a due livelli:

```
vault/
├── vault.cvconf                config, key slot, policy (unico file "globale")
├── d/
│   └── AB/CDEF…XYZ/            = base32(HMAC-SHA256(K_mac, dirId)), shard di 2 caratteri
│       ├── 0f3a…==.cvf         file  — nome = base64url(AES-SIV(K_names, dirId ‖ nome))
│       ├── 91bc…==.cvd         sottodirectory — contiene il dirId della figlia + metadati
│       └── a7e2…==.cvn         overflow per nomi lunghi (> 220 B cifrati)
├── .trash/                     cestino
└── .versions/                  versioni dei soli file marcati
```

- **AES-SIV per i nomi**: cifratura *deterministica*, indispensabile perché `apri("relazione.pdf")`
  deve poter calcolare il nome cifrato senza elencare e decifrare l'intera directory. Il `dirId`
  del genitore entra nel calcolo, quindi lo stesso nome in cartelle diverse produce ciphertext
  diversi.
- **Albero piatto su hash del dirId**: rinominare o spostare una directory con 10.000 file costa
  la riscrittura di **un** file (il `.cvd` del genitore). Nasconde inoltre la profondità reale.
- **Shard di 2 caratteri**: evita directory con decine di migliaia di entry, che degradano su NTFS
  e mettono in crisi i client di sincronizzazione.
- **Path traversal impossibile per costruzione**: un nome decifrato non viene mai concatenato a un
  percorso di filesystem. Il percorso su disco dipende solo dall'HMAC del dirId. Un nome decifrato
  che contenesse `../` sarebbe innocuo, e viene comunque rifiutato in validazione.

**Cosa resta visibile a chi guarda il disco** — da dichiarare esplicitamente nel THREAT_MODEL:
il numero di file, la dimensione approssimativa di ciascuno (±32 KiB), le date di modifica sul
filesystem ospite, e il fatto che si tratti di un vault CryptoVault. **Non** sono visibili: nomi,
contenuti, struttura delle cartelle, gerarchia, metadati.

### 3.4 L'astrazione VFS (il ponte verso il mount)

```rust
pub trait VaultFs {
    fn stat(&self, path: &VPath) -> Result<Metadata>;
    fn read_dir(&self, path: &VPath) -> Result<Vec<DirEntry>>;
    fn read_at(&self, h: FileHandle, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn write_at(&self, h: FileHandle, offset: u64, buf: &[u8]) -> Result<usize>;
    fn truncate(&self, h: FileHandle, size: u64) -> Result<()>;
    fn create(&self, path: &VPath, kind: NodeKind) -> Result<FileHandle>;
    fn rename(&self, from: &VPath, to: &VPath) -> Result<()>;
    fn remove(&self, path: &VPath, mode: RemoveMode) -> Result<()>;
    fn flush(&self, h: FileHandle) -> Result<()>;
}
```

L'API è **offset-based dal primo giorno**. È la differenza tra "il mount è una milestone" e "il
mount richiede di riscrivere tutto": FUSE e WinFsp parlano esattamente questo linguaggio, quindi
l'adapter di M14 sarà una traduzione meccanica. In v1 l'unica implementazione è `DirectVaultFs`.

### 3.5 Sessioni con applicazioni esterne

Il flusso "doppio click → si apre in Word → salvo → si richiude cifrato":

1. **Apertura** — decifratura in una directory temporanea di sessione (`0700`, nome casuale, una
   per vault sbloccato); la sessione viene registrata in un journal locale.
2. **Lancio** — apertura con l'applicazione predefinita del sistema.
3. **Osservazione** — un watcher (`notify`) segue il file. Al `write` seguito da ~800 ms di
   quiescenza, il contenuto viene ri-cifrato nel vault. Il debounce non è un dettaglio: molti
   editor salvano con una sequenza scrivi-rinomina-scrivi che genererebbe eventi a raffica.
4. **Chiusura** — alla chiusura dell'app, al lock, alla scadenza dell'inattività o all'uscita:
   ultimo flush, poi rimozione del temporaneo.
5. **Recupero da crash** — il journal sopravvive: all'avvio successivo CryptoVault trova i
   temporanei orfani, offre di reimportarne le modifiche e li elimina.

**Limite dichiarato, non nascosto.** Durante la sessione il file esiste in chiaro sul disco, e la
"cancellazione sicura" con sovrascrittura **non garantisce nulla** su SSD (wear leveling), su
APFS e Btrfs (copy-on-write) né in presenza di snapshot di Time Machine. Dove possibile usiamo
storage volatile (`/dev/shm` su Linux, ramdisk opzionale su macOS); altrove sovrascrittura
best-effort e unlink, con l'avvertenza scritta in chiaro nell'interfaccia. È esattamente il
compromesso che il mount virtuale di M14 eliminerà.

### 3.6 Modalità sigillata, anteprime e riautenticazione

**Vault sigillato** (scelto alla creazione, registrato in `vault.cvconf` e autenticato con
`K_mac`): niente drag-out, niente "esporta in chiaro", niente apertura con app esterne. I file si
consultano solo con i viewer interni e si condividono solo come `.ecf` cifrato.

Va detto con precisione cosa questa modalità è e cosa non è: **è una policy applicativa, non una
garanzia crittografica**. Chi possiede la password possiede i dati e può sempre estrarli con la
CLI o con una build modificata. Protegge dall'errore distratto e dall'uso improprio da parte di
chi ha accesso temporaneo alla sessione, non dal proprietario del vault. Scriverlo nel
THREAT_MODEL e nell'interfaccia.

**Anteprime disattivate di default**, attivabili per singola cartella con una spunta, previa
**riautenticazione con la password**. Il flag vive nei metadati cifrati della directory, quindi
segue il vault su tutti i dispositivi. Esiste inoltre un interruttore globale per macchina che
disabilita comunque ogni anteprima.

Il vero motivo della riautenticazione non è lo spazio né la privacy delle miniature — quelle non
toccano mai il disco. È la **superficie d'attacco**: generare un'anteprima significa dare in pasto
a un decoder un file potenzialmente ostile. Attivarla è una decisione consapevole, e vale la pena
che costi una password.

**Viewer interni:**
- Immagini (PNG, JPEG, GIF, WebP) e testo/codice/Markdown/CSV: crate Rust puri, memory-safe,
  in-process.
- **PDF: sempre in `cv-render`, processo figlio isolato.** Riceve i byte già decifrati su pipe,
  restituisce pixel. Nessun accesso al filesystem, alla rete o alla memoria delle chiavi
  (seatbelt su macOS, job object a bassa integrità su Windows, seccomp/Landlock su Linux). Se il
  parser viene sfruttato, l'attaccante conquista un processo vuoto.

### 3.7 Vincoli imposti dalla sincronizzazione cloud

Aver scelto il cloud come caso d'uso di primo livello vincola il design in modo permanente:

- **Nessun indice globale mutabile.** L'elenco dei file si ricava dal filesystem. Un indice
  condiviso sarebbe il punto di conflitto garantito fra due macchine.
- **L'indice di ricerca e l'audit log sono locali**, in `AppData`/`Application Support`, per
  macchina, cifrati con `K_meta`/`K_audit`, ricostruibili, **mai** dentro la cartella sincronizzata.
- **Scritture atomiche**: temporaneo nella stessa directory, `fsync`, `rename`. Un file
  parzialmente sincronizzato non deve mai apparire valido.
- **Rilevamento conflitti**: riconosciamo i pattern dei client (`(conflicted copy)`,
  `(Simone's MacBook)`, ` 2`) e li presentiamo come conflitti risolvibili, **con il nome
  decifrato**, invece di lasciarli come spazzatura illeggibile.
- **Lock cooperativo**: `.cvlock` con id macchina e heartbeat. Se un'altra macchina lo aggiorna,
  avvisiamo prima di sbloccare. Avviso, non blocco: un lock stale non deve mai rendere un vault
  inaccessibile.
- **Placeholder online-only** (OneDrive Files On-Demand, iCloud "ottimizza spazio"): vanno
  riconosciuti e materializzati su richiesta, altrimenti la verifica d'integrità scarica
  silenziosamente decine di GB.

### 3.8 Backup e archivio

- **Backup incrementale** verso cartella o disco esterno: copia dei soli file cifrati modificati
  (i file sono già cifrati, il backup non decifra mai nulla), verifica d'integrità al termine,
  pianificazione opzionale.
- **`.cvarchive`**: l'intero vault in un unico file. Non è un secondo formato crittografico — è un
  contenitore (tar) dei file **già cifrati** più il config e un manifesto, con parità
  Reed-Solomon opzionale sull'insieme. Comodo per l'archiviazione a lungo termine e per spostare
  un vault senza trascinarsi decine di migliaia di file. Si apre con la stessa password.

---

## 4. Roadmap

Ordinata secondo la priorità dichiarata: **prima un vault che usi tu**, poi il prodotto completo,
poi il rilascio pubblico. Stime in settimane-uomo per uno sviluppatore singolo assistito da
Claude Code.

### Fase 1 — Un vault utilizzabile (≈12 settimane)

**M0 — Fondamenta** (1 sett.)
Workspace Cargo, `rust-toolchain.toml`, clippy pedantic, `deny.toml`. CI su Windows/macOS/Linux
con `cargo-deny` e `cargo-audit`. Licenza doppia, `SECURITY.md` con policy di disclosure.
**`docs/THREAT_MODEL.md`** — contro chi difendiamo (accesso al disco, provider cloud malevolo,
furto del portatile a vault chiuso) e contro chi **no** (malware con i nostri privilegi,
keylogger, accesso alla RAM, evil maid). Scritto prima del codice: è il documento che stabilisce
cosa è un bug e cosa non lo è. Prima stesura di `FORMAT_SPEC.md`. Scheletro del **manuale utente**
IT/EN e `CONTRIBUTING.md` con la Definition of Done della sezione 6, così le regole esistono prima
del codice a cui si applicano.

**M1 — Core crittografico e formato** (3,5 sett.) — nessuna UI
Port delle primitive da Cryptera con `zeroize` su ogni materiale di chiave; HKDF-SHA256, AES-SIV,
XChaCha20 come `alg_id` alternativo. Key slot, wrap/unwrap del MasterSeed, MAC del config, cambio
password, generazione della recovery key a 24 parole. Header, chunk, metadati CBOR, cifratura dei
nomi, mappatura dirId, entrambe le modalità file.
**Vettori di test congelati** in `tests/vectors/`: un vault generato con seed e nonce fissi e i
suoi output byte per byte. Da qui in poi ogni modifica del formato deve rompere questi test in
modo rumoroso e consapevole. Property test con `proptest` su dimensioni e offset arbitrari:
qualunque bit alterato nel ciphertext deve produrre un errore di autenticazione, **mai** un dato
sbagliato silenzioso. Fuzzing su header, chunk troncati, metadati e nomi ostili.
*Criterio di uscita: il formato è specificato, implementato, testato e fuzzato prima che esista
una riga di interfaccia. È la cosa che non potremo più cambiare con leggerezza dopo il primo
utente reale.*

**M2 — Vault, VFS e CLI interna** (2,5 sett.)
Create/unlock/lock, CRUD di file e directory, rename, walk. Il trait `VaultFs` e `DirectVaultFs`.
Import/export ricorsivo con progresso, pausa e annullamento (riusando il pattern `ControlFlags`).
CLI: `init | unlock | ls | add | get | rm | mv | verify`. Primi benchmark di scala su vault
sintetici (50.000 file piccoli, file da 20 GB).

**M3 — GUI v1** (3 sett.)
Tauri v2 + Svelte + TS + Vite, CSP con `connect-src 'none'`. Onboarding con indicatore di robustezza
della password, avviso inequivocabile sulla perdita della password, scelta della policy
normale/sigillato. Sblocco, gestione multi-vault. File browser **virtualizzato** (albero + lista,
selezione multipla, drag & drop, ordinamento, breadcrumb) — la virtualizzazione va messa subito,
non aggiunta dopo. Coda operazioni con progresso. **Auto-lock** con le tre politiche. Tray con
blocco immediato. Tema chiaro/scuro/sistema, i18n IT/EN.

**M4 — Sessioni con applicazioni esterne** (2 sett.)
Il flusso della sezione 3.5 completo: journal, watcher con debounce, cleanup, recupero da crash.
Matrice di test per applicazione — Word, Excel, Anteprima, VS Code, GIMP salvano ognuno in modo
diverso, ed è qui che si concentrano le sorprese.
*Criterio di uscita: **CryptoVault è un vault vero e lo usi ogni giorno**.*

### Fase 2 — Prodotto completo (≈11 settimane)

**M5 — Ricerca, anteprime e viewer** (2,5 sett.)
Indice locale dei nomi e dei tag con fuzzy match, ricostruzione incrementale. Anteprime opt-in per
cartella con riautenticazione, generate **solo in memoria**, cache LRU azzerata al lock. Viewer
immagini e testo in-process. **`cv-render`**: processo isolato e sandboxed per il PDF, con il
protocollo IPC e i profili di sandbox per macOS e Windows.

**M6 — Cestino, versioni, integrità, archiviazione** (2,5 sett.)
Cestino con ripristino e svuotamento. Versioning per singolo file con retention configurabile.
`verify`: scansione integrale che controlla ogni tag AEAD **senza mai materializzare il
plaintext**. Modalità ARCHIVED: compressione e parità Reed-Solomon, con riparazione.

**M7 — Hardening della sincronizzazione** (1,5 sett.)
Rilevamento e risoluzione conflitti in UI, lock cooperativo con heartbeat, gestione dei
placeholder online-only, test con vault reali dentro Dropbox, iCloud e OneDrive.

**M8 — Import/export, backup, archivio** (2 sett.)
Import di cartelle con cancellazione sicura opzionale dell'originale (con l'avvertenza della
sezione 3.5). **Export in `.ecf` compatibile con Cryptera**: un file estratto dal vault e cifrato
con password monouso, apribile da chiunque abbia Cryptera — il ponte naturale fra i due progetti,
che risolve la condivisione senza inventare un protocollo. Backup incrementale e `.cvarchive`.

**M9 — Integrazione con il sistema** (2,5 sett.)
Associazione di `vault.cvconf`, hotkey globale di blocco, tray completa. **Menu contestuale**:
Finder Sync Extension su macOS (Swift, bundle firmato) e shell extension su Windows. È codice
nativo e diverso per ogni piattaforma, ed è la milestone con più attriti di firma e
pacchettizzazione. Linux escluso (nessun ambiente di test manuale).

### Fase 3 — Rilascio (≈2 settimane)

**M10 — Release engineering**
Installer per i tre OS (MSI/NSIS, DMG universale, deb/rpm/AppImage), firma Authenticode,
notarizzazione Apple, updater firmato manuale, `SHA256SUMS.txt`, CHANGELOG, documentazione utente
IT/EN, pagina di release. Riutilizzabile quasi interamente dal setup di Cryptera.
**Linux esce come beta dichiarata** (vedi rischi).

### Fase 4 — Sicurezza avanzata e mount

- **M11** — UI della recovery key, keychain OS e biometria (Touch ID, Windows Hello): riempiono
  gli slot 1 e 2, **nessun cambio di formato**.
- **M12** — Keyfile e FIDO2 `hmac-secret`: slot 3.
- **M13** — Negabilità plausibile, da valutare con dati d'uso reali. Nota tecnica: con lo storage
  per-file un vault nascosto è strutturalmente debole, perché numero e dimensione dei file
  restano visibili. La password di emergenza (slot 4, MasterSeed diverso) è invece a costo quasi
  nullo e va valutata per prima.
- **M14** — **Disco virtuale**: adapter FUSE (macOS/Linux) e WinFsp (Windows) sopra `VaultFs`.
  Elimina definitivamente i temporanei in chiaro. Da affrontare a prodotto stabile: è la parte con
  più attriti di distribuzione (dipendenze esterne, permessi, estensioni di sistema su macOS).

**Totale Fase 1–3: ≈25 settimane-uomo.** Il primo build che userai davvero arriva a ≈12.

> **Nota onesta sullo scope.** Le risposte di questo giro hanno aggiunto circa 6 settimane
> rispetto alla stima iniziale: viewer con processo isolato, backup e archivio, menu contestuale
> nativo su due OS, metadati per-file e progettazione per il caso generale. Sono tutte scelte
> difendibili, ma se a metà percorso vorrai accelerare, i tre candidati al taglio nell'ordine
> sono: **M9 menu contestuale** (nativo, costoso, sostituibile dal drag & drop),
> **`.cvarchive`** (una copia della cartella fa quasi lo stesso lavoro) e **il PDF in processo
> isolato** (rimandabile a dopo il rilascio, tenendo i soli viewer Rust puri).

---

## 5. Rischi

| Rischio | Impatto | Mitigazione |
|---|---|---|
| Cambio di formato dopo il primo utente | Alto — dati a rischio | Formato congelato con vettori di test in M1; campo versione e migrazione esplicita obbligatoria |
| Il chiaro nei temporanei non è cancellabile davvero su SSD/CoW | Medio, reputazionale se taciuto | Dichiarato nel THREAT_MODEL e in UI; storage volatile dove possibile; M14 lo elimina |
| **Linux mai provato a mano** | Medio | CI completa sui tre OS; **Linux dichiarato beta alla 1.0**, con una fase di test pubblica prima di rimuovere l'etichetta |
| Comportamenti di salvataggio bizzarri delle app esterne | Medio — perdita di modifiche | Journal, debounce, versioning; matrice di test per applicazione in M4 |
| Client di sync che corrompono o duplicano | Medio | Scritture atomiche, nessun indice condiviso, M7 dedicata, test su cloud reali |
| Parser PDF come vettore d'attacco | Medio | Processo isolato senza accesso alle chiavi; anteprime opt-in con riautenticazione |
| Menu contestuale nativo: firma e distribuzione | Medio | Isolato in M9, tagliabile; prototipo di firma su macOS già in M8 |
| Complessità del mount sottovalutata | Medio | Isolato in M14 dietro un trait progettato apposta; il prodotto è completo senza |
| Notarizzazione Apple e firma Windows | Bloccante al rilascio | Account Apple Developer (99 $/anno) e certificato da procurare **durante M8**, non a M10 |
| Argon2id a 256 MiB su macchine deboli | Basso | Calibrazione automatica alla creazione, parametri scritti nel config |

---

## 6. Metodo di lavoro

Queste regole valgono per ogni riga di codice del progetto, dalla prima all'ultima. Non sono
buone intenzioni: sono condizioni di merge, verificate dalla CI dove è possibile verificarle
automaticamente.

### 6.1 Definition of Done

Una funzionalità è **finita** solo quando tutti e sei i punti sono veri. Non cinque.

1. **È verificata da un test.** Nessuna funzionalità entra senza il test che la esercita. Test
   unitari accanto al codice, test di integrazione in `tests/`, property test dove l'input è
   variabile, vettori congelati dove il formato è in gioco. Un test che non fallirebbe se la
   funzione fosse rotta non conta come test.
2. **Il codice è strutturato e manutenibile.** Un modulo, una responsabilità. Funzioni brevi con
   un solo livello di astrazione. Errori tipizzati con `thiserror`, mai `unwrap()` fuori dai test,
   mai `panic!` su input dell'utente. Nessuna duplicazione: alla seconda occorrenza si estrae.
3. **Il codice è commentato.** Doc comment `///` su **ogni** elemento pubblico — i crate portano
   `#![deny(missing_docs)]`, quindi la CI lo impone. I commenti nel corpo spiegano **perché**, non
   cosa: il cosa lo dice il codice. Ogni scelta crittografica non ovvia porta accanto la sua
   motivazione e, dove serve, il riferimento allo standard.
4. **Il manuale utente è aggiornato nello stesso commit.** Ogni funzione visibile all'utente
   aggiorna la sua sezione in `docs/manual/it/` e `docs/manual/en/`. Il manuale non si scrive alla
   fine — a fine progetto nessuno ricorda perché un'opzione esiste. Si scrive mentre la funzione
   è fresca, e il codice va organizzato **perché sia descrivibile**: se una funzione è difficile
   da spiegare in due frasi, quasi sempre il problema è nella funzione, non nella spiegazione.
5. **Il codice modificato è stato ricontrollato.** Dopo ogni modifica o aggiunta si rilegge il
   codice toccato e si riesegue la verifica completa **prima** del commit. Vale anche per le
   modifiche piccole: le regressioni arrivano quasi sempre da lì.
6. **Il CHANGELOG è aggiornato** se la modifica è visibile all'utente.

### 6.2 Il comando di verifica

Una sola cosa da ricordare, che gira in locale e in CI, identica:

```
./scripts/check.sh          # macOS/Linux
.\scripts\check.ps1         # Windows
```

Esegue in sequenza: `cargo fmt --check`, `cargo clippy` con warning trattati come errori,
`cargo test` su tutto il workspace, `cargo doc` senza warning, `cargo deny check`. Se fallisce,
non si committa. Non esistono eccezioni "tanto è una modifica piccola".

### 6.3 Copertura richiesta per area

| Area | Requisito |
|---|---|
| `cv-crypto`, `cv-format` | Ogni funzione pubblica testata **e ogni ramo d'errore esercitato**. Vettori di test congelati. Fuzzing su tutti i parser |
| `cv-vault`, `cv-vfs` | Test di integrazione su vault reali temporanei; roundtrip completo; casi limite di concorrenza |
| `cv-ops` | Test su file di scala reale (generati, non committati); annullamento e ripresa dei job |
| UI | Test dei componenti con stato non banale; verifica manuale documentata per il resto |
| Prestazioni | Benchmark in CI con soglie: una regressione oltre il 20% fa fallire la build |

Nessun obiettivo numerico di copertura percentuale: inseguire una percentuale produce test che
esistono per la statistica. Il criterio è che **ogni comportamento descritto nel manuale abbia un
test che lo dimostra**.

### 6.4 Commit, branch e push

- **Commit frequenti e atomici**: un commit = una modifica coerente e completa, con la sua
  verifica passata. Meglio dieci commit piccoli che uno da 2.000 righe.
- **Conventional Commits**: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `perf:`,
  `sec:`. Rende il CHANGELOG generabile e la storia leggibile.
- **Push autorizzato** dall'autore del progetto: si pusha spesso, senza chiedere ogni volta.
- **Branch**: M0 direttamente su `main` (bootstrap). Da M1 in poi un branch per milestone
  (`feat/m1-core-crypto`) con Pull Request, così la CI fa da cancello e resta una traccia di
  revisione. `main` deve essere sempre verde e sempre compilabile.
- **Mai** committare segreti, chiavi private, vault di prova o file di test di grandi dimensioni.

### 6.5 Lingua del progetto

**Codice, commenti, doc comment, messaggi di commit, issue e PR in inglese**; il progetto è
open source e l'inglese è la lingua che consente a chiunque di contribuire. **Documentazione
rivolta all'utente — manuale, README, note di rilascio, interfaccia — in italiano e inglese.**
È una convenzione, non un dogma: se preferisci i commenti in italiano si cambia, ma va deciso ora
e non a metà strada.

---

## 7. Principi non negoziabili

1. **Il plaintext non tocca il disco** se non dentro una sessione esplicita, tracciata e revocabile.
2. **Nessuna rete** salvo l'updater, su richiesta esplicita. `connect-src 'none'` nella webview.
3. **Nessuna telemetria**, nessun crash reporter automatico.
4. **Ogni chiave è `Zeroizing`**, sempre. `mlock`/`VirtualLock` sul materiale di chiave per
   impedirne lo swap su disco, core dump disabilitati.
5. **Il formato è la specifica**, non l'implementazione: `FORMAT_SPEC.md` è normativo e si
   aggiorna *prima* del codice.
6. **Fallire in modo rumoroso**: un tag di autenticazione non valido è un errore, mai un warning,
   mai un dato restituito a metà.
7. **I limiti si dichiarano.** Un'app di sicurezza che promette più di quanto mantiene è peggio di
   una che documenta con precisione dove si ferma.

---

## 8. Scelte tecniche minori, già prese

Non richiedono discussione, ma vanno messe a verbale:

| Voce | Scelta | Perché |
|---|---|---|
| Dimensione del chunk | **32 KiB** | Compromesso standard fra overhead (0,085%) e costo della scrittura casuale |
| Estensioni | `.cvf` file, `.cvd` directory, `.cvn` nomi lunghi, `vault.cvconf`, `.cvarchive` | Brevi, distintive, non collidono con nulla di diffuso |
| Recovery key | 24 parole da wordlist BIP39 | Trascrivibile a mano senza ambiguità, con checksum, già familiare |
| Cancellazione file | Semplice unlink | Il contenuto è cifrato e la sua chiave vive solo nell'header eliminato: la cancellazione crittografica è implicita |
| Serializzazione metadati | CBOR | Compatto, campi sconosciuti ignorabili, compatibilità in avanti |
| Compressione (modalità ARCHIVED) | zstd come default, LZMA2 opzionale | zstd ha il miglior rapporto velocità/compressione; LZMA2 per chi vuole il massimo |
| Avvio automatico al login | Non implementato | Non richiesto; aggiungibile in un pomeriggio se servirà, sempre disattivato di default e sempre con avvio bloccato |
| Attributi estesi e tag di sistema | Non conservati | Poco portabili fra OS, complessità sproporzionata al beneficio |

---

## 9. Stato e prossimi passi

- [x] Piano approvato nelle decisioni fondamentali.
- [x] **M0 — Fondamenta**: repository, workspace Cargo, CI sui tre OS, licenze, documentazione,
      THREAT_MODEL, bozza di FORMAT_SPEC, scheletro del manuale utente.
- [x] **M1 — Core crittografico e formato**: primitive (Argon2id, AEAD con agilità algoritmica,
      HKDF, AES-SIV), key slot, header e chunk, metadati, nomi cifrati, mappatura directory,
      `vault.cvconf` autenticato, vettori congelati e quattro target di fuzzing. 229 test.
- [x] **M2 — Vault, VFS e CLI interna**: vault su disco con scritture atomiche, lettura e
      scrittura a offset, il trait `VaultFs` con `DirectVaultFs`, e la CLI `cryptovault`
      (init, ls, mkdir, add, get, rm, mv, verify, inspect). 320 test.
      *Rimandato a M3:* i job di import/export con progresso e annullamento, e i benchmark
      di scala con soglie in CI — al loro posto ci sono test di scala moderati (500 file in
      una directory, 200 directory sugli shard).
- [ ] **M3 — Interfaccia desktop**: Tauri + Svelte, browser dei file virtualizzato,
      multi-vault, auto-lock.

Ogni milestone completata aggiorna questa sezione e il CHANGELOG.
