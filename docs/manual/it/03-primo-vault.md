# 3. Creare il primo vault

> **CryptoVault è alla milestone M3.** L'applicazione funziona, crea vault e li
> apre. Portare i file *dentro* un vault dal tuo disco è la milestone
> successiva, quindi un vault creato oggi è un posto dove tenere cartelle, non
> file. Non spostarci ancora niente a cui tieni.

Un vault è una cartella. Tutto quello che contiene è cifrato: il contenuto dei
file, i loro nomi e la forma delle cartelle in cui stanno. Scegli tu dove
mettere quella cartella e come chiamarla, e da lì in poi la sblocchi con una
password.

## Crearne uno

Premi **Crea un vault**. Quattro cose da decidere, e una sola è difficile.

**Un nome.** Come lo chiamerai nell'elenco dei vault. Non è cifrato: lo conserva
l'applicazione, non il vault, e serve a te per distinguere due vault.

**Una posizione.** Premi **Scegli…** e indica la cartella in cui vuoi che il
vault stia. CryptoVault ci crea dentro una nuova cartella, con il nome del
vault, e ti mostra il percorso completo prima di procedere. Un vault su un disco
esterno o dentro una cartella Dropbox o iCloud va benissimo: è una delle cose
per cui questo strumento è fatto.

**Una password.** È quella difficile, ed è l'argomento del resto del capitolo.

**Se è sigillato.** Lascialo disattivato, a meno che tu non sappia di volerlo —
vedi sotto.

## La password

Non è recuperabile. Non da noi, non da nessuno. Non esiste un link per
reimpostarla, un indirizzo di assistenza, una porta di servizio o una seconda
copia della tua chiave conservata da qualche parte. Se dimentichi la password,
il vault è una cartella di rumore e tale resta.

È il senso stesso di questo strumento. Ed è anche, di gran lunga, il modo più
comune in cui si perdono dati con software di questo tipo: non per colpa di un
attaccante, ma della propria memoria. Trattala per la decisione che è:

- Usa una **frase lunga** che non puoi dimenticare — più parole senza relazione
  fra loro — oppure un **gestore di password**, che è la risposta migliore se
  già ne usi uno.
- Non usare una password che usi altrove. Se compare in una fuga di dati da
  un'altra parte, diventa la prima cosa che si prova qui.
- Se serve, scrivila e mettila in un posto sicuro. Una frase su un foglio in un
  cassetto è un rischio che hai scelto; una frase che non ricordi è una
  certezza.

### L'indicatore di robustezza

La barra sotto il campo della password è una stima approssimativa basata su
lunghezza e varietà, ed è onesta sul fatto di non essere altro. Non può dirti se
la tua password è *indovinabile*: `Password123!` prende un buon punteggio ed è
in ogni elenco che un attaccante possiede. Una frase lunga e ordinaria prenderà
un punteggio più basso e sarà molto più forte.

Prendi un punteggio scarso come un avvertimento, e uno buono come niente.

### Perché lo sblocco è lento

Di proposito, ed è qui che conta spiegarlo: CryptoVault impiega circa un secondo
a trasformare la tua password in una chiave. Quel secondo è lo stesso che un
attaccante deve spendere per ogni password che prova. È ciò che trasforma una
velocità di milioni di tentativi al secondo in pochi al secondo, ed è la
differenza fra una frase decente che è sicura e una che è solo scomoda.

Quando crea il vault, l'applicazione misura la tua macchina e sceglie parametri
che costino circa un secondo *lì*: un vault creato su un computer veloce è più
difficile da attaccare di uno creato su un computer lento. I parametri sono
scritti nel vault, quindi si apre comunque su qualsiasi macchina.

## I vault sigillati

Un vault sigillato non lascia uscire i file in chiaro: non si possono estrarre
in forma leggibile né aprire con altre applicazioni. Li consulti dentro
CryptoVault e li condividi solo cifrati.

Due cose da capire prima di sceglierlo:

- È una **regola applicata da questo programma**, non qualcosa che la
  crittografia rende impossibile. Chi ha la password può tirare fuori i dati in
  un altro modo. Protegge dall'abitudine e dalla fretta, non da una persona
  determinata.
- Lo scegli quando crei il vault. Consideralo definitivo.

Va bene per quel piccolo insieme di documenti su cui sei più attento, e dà
fastidio ovunque altro. Alla maggior parte delle persone serve disattivato.

## Che cosa succede dopo

Il vault viene creato e **lasciato bloccato**. È voluto: creare un vault non è
un modo per ritrovarsene uno aperto, e ridigitare subito la password è la
verifica più economica possibile di aver scritto la prima volta quello che
intendevi.

Se il secondo tentativo non funziona, lo scopri adesso — con il vault vuoto — e
non fra sei mesi.

Guarda nella cartella che hai scelto e troverai una nuova cartella con il nome
del vault, che contiene un file `vault.cvconf` e una directory `d`. Quello è
tutto il vault. Copiare quella cartella copia il vault, cifrato; cancellarla
cancella il vault, e nient'altro sa come riportarlo indietro.

## Dove si trova l'elenco dei vault

CryptoVault ricorda quali vault hai e dove sono, così non ti chiede di
ritrovarli ogni mattina. Quell'elenco sta con l'applicazione, non con i vault:

| Sistema | Posizione |
|---|---|
| macOS | `~/Library/Application Support/app.cryptovault.desktop/` |
| Windows | `%APPDATA%\app.cryptovault.desktop\` |
| Linux | `~/.config/app.cryptovault.desktop/` |

Contiene nomi e percorsi, e nient'altro: nessuna chiave, e nessuna traccia di
quale vault fosse aperto. Cancellarlo fa perdere l'elenco, mai un vault: indica
di nuovo le cartelle a CryptoVault con **Aggiungi un vault esistente** e torna
tutto.
