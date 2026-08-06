<div align="center">

# CryptoVault

**Un'area cifrata sul disco dove i file si usano davvero, non si archiviano soltanto.**

[![CI](https://github.com/gh0st032395/CryptoVault/actions/workflows/ci.yml/badge.svg)](https://github.com/gh0st032395/CryptoVault/actions/workflows/ci.yml)
[![Licenza](https://img.shields.io/badge/licenza-MIT%20OR%20Apache--2.0-blue.svg)](#licenza)
[![Stato](https://img.shields.io/badge/stato-pre--alpha%20(M0)-orange.svg)](#stato-del-progetto)

[English](README.md) · [Piano di sviluppo](PLAN.md) · [Modello di minaccia](docs/THREAT_MODEL.md) · [Specifica del formato](docs/FORMAT_SPEC.md)

</div>

---

## ⚠️ Stato del progetto

**CryptoVault non funziona ancora. Non avvicinargli dati reali.**

Il progetto è alla milestone **M0** — fondamenta. Esistono il workspace, la
pipeline di verifica, il modello di minaccia e la specifica del formato. Non
esistono né il vault, né la cifratura, né l'interfaccia. La prima build che vale
la pena usare tutti i giorni arriva a fine M4; vedi la [roadmap](#roadmap).

Questo avviso sparirà quando smetterà di essere vero.

---

## Che cos'è

CryptoVault crea vault cifrati sul disco. Ne sblocchi uno con una password,
sfogli i tuoi file, li apri, li modifichi e li richiudi — e nulla esiste in
chiaro se non per la durata di una sessione che hai avviato deliberatamente.

Nessun cloud nostro, nessun account, nessuna telemetria. L'unica connessione di
rete che l'applicazione fa è il controllo degli aggiornamenti, e solo quando lo
chiedi tu.

- **I file restano usabili.** Doppio click su un documento e si apre
  nell'applicazione che usi di solito; viene ri-cifrato quando la chiudi. È
  previsto anche un disco virtuale montato, che elimina del tutto il file
  temporaneo.
- **Pensato per il cloud.** Ogni file del vault è un file cifrato sul disco,
  quindi Dropbox, iCloud, Drive e OneDrive lo sincronizzano in modo
  incrementale. Nomi, struttura delle cartelle e contenuti sono cifrati sul tuo
  computer.
- **Niente è nascosto a te.** Il [modello di minaccia](docs/THREAT_MODEL.md)
  elenca ciò da cui CryptoVault **non** protegge, e cosa resta comunque visibile
  quando tutto funziona. Quella sezione è più lunga di quella rassicurante.

## Rapporto con Cryptera

[Cryptera](https://github.com/gh0st032395/Cryptera) — dello stesso autore —
cifra un file in un `.ecf` e viceversa. È una trasformazione one-shot: il file
viene letto, cifrato e scritto per intero.

Un vault è un problema diverso. Servono accesso casuale, scrittura incrementale,
una gerarchia di directory e uno stato sbloccato/bloccato: cose che un formato
whole-file non può offrire — leggere 4 KiB da un `.ecf` significa decifrarlo tutto.

Quindi CryptoVault riusa le *primitive* di Cryptera e la sua disciplina
(Argon2id, AES-256-GCM, `zeroize`, Reed-Solomon, il rigore su test e fuzzing) e
riprogetta il *formato*. I due progetti restano collegati nella direzione che
conta: CryptoVault esporterà file come `.ecf` compatibili con Cryptera, così la
condivisione funziona senza inventare un protocollo.

## Il design in breve

| | |
|---|---|
| **Cifratura contenuti** | AES-256-GCM a chunk di 32 KiB, ognuno autenticato per conto suo. Overhead 0,085% |
| **Derivazione chiavi** | Argon2id, 256 MiB di default, calibrato alla creazione del vault |
| **Gerarchia chiavi** | Password → KEK → master seed avvolto, in key slot indipendenti |
| **Nomi** | AES-SIV, deterministico, così una ricerca non richiede di scandire la directory |
| **Directory** | Collocate tramite HMAC di un identificatore casuale: rinominare una cartella con 10.000 file riscrive un solo file |
| **Storage** | Un file cifrato per ogni file del vault — adatto al sync, nessun indice globale su cui litigare |
| **Stack** | Rust + Tauri v2 + Svelte + TypeScript |

I key slot meritano una frase a parte: ogni metodo di sblocco avvolge lo *stesso*
master seed in modo indipendente, quindi aggiungere Touch ID o una recovery key
più avanti riscrive 48 byte invece di ri-cifrare tutti i file. È per questo che
stanno nella versione 1 del formato anche se per ora è implementato solo lo slot
della password.

Tutti i dettagli in [`docs/FORMAT_SPEC.md`](docs/FORMAT_SPEC.md).

## Roadmap

| | Milestone | |
|---|---|---|
| ✅ | **M0** Fondamenta — workspace, CI, modello di minaccia, specifica del formato | fatta |
| ⬜ | **M1** Core crittografico e formato, con vettori di test congelati e fuzzing | prossima |
| ⬜ | **M2** Vault, astrazione filesystem, CLI interna | |
| ⬜ | **M3** Interfaccia desktop — browser, multi-vault, auto-lock | |
| ⬜ | **M4** Apertura dei file con applicazioni esterne | ← *prima build davvero usabile* |
| ⬜ | **M5** Ricerca, anteprime opt-in, viewer PDF isolato | |
| ⬜ | **M6** Cestino, versioni per file, verifica integrità, modalità archiviata | |
| ⬜ | **M7** Hardening della sincronizzazione — conflitti, lock cooperativo | |
| ⬜ | **M8** Import/export, condivisione `.ecf`, backup e archivio unico | |
| ⬜ | **M9** Integrazione col sistema — tray, menu contestuale, hotkey di blocco | |
| ⬜ | **M10** Rilascio — installer firmati per Windows, macOS e Linux | |
| ⬜ | **M11+** Recovery key, biometria, chiavi hardware, disco virtuale | |

Il piano completo, con il ragionamento dietro ogni decisione, è in
[`PLAN.md`](PLAN.md).

## Compilare dai sorgenti

Serve la toolchain Rust; la versione esatta è fissata in `rust-toolchain.toml` e
`rustup` la scarica da sola.

```bash
git clone https://github.com/gh0st032395/CryptoVault.git
cd CryptoVault
cargo build --workspace
```

Prima di ogni commit si esegue il comando di verifica, identico a quello della CI:

```bash
./scripts/check.sh
```

Su Windows:

```powershell
.\scripts\check.ps1
```

## Contribuire

Leggi prima [`CONTRIBUTING.md`](CONTRIBUTING.md). In breve: ogni funzionalità
arriva con il test che la dimostra, con doc comment che spiegano il *perché*, e
con la sua sezione di manuale utente aggiornata nello stesso commit.

Le segnalazioni di sicurezza vanno in [`SECURITY.md`](SECURITY.md), non
nell'issue tracker pubblico.

## Licenza

Doppia licenza [MIT](LICENSE-MIT) o [Apache 2.0](LICENSE-APACHE), a tua scelta —
gli stessi termini di Cryptera.

Per uno strumento che ti chiede di affidargli i tuoi file, poter leggere il
codice fa parte dell'offerta.
