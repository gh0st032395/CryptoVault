# 1. Introduzione

> **CryptoVault non è finito.** Mentre scriviamo non esiste un'applicazione
> funzionante: il progetto è alla milestone M0, che ha costruito le fondamenta,
> il modello di minaccia e la specifica del formato. Non mettere ancora in un
> vault di CryptoVault niente a cui tieni.

## Che cos'è CryptoVault

CryptoVault crea **vault**: aree cifrate sul tuo disco dove i file restano
utilizzabili. Sblocchi un vault con una password, sfogli i tuoi file, li apri,
li modifichi e lo richiudi. Finché il vault è bloccato, tutto quello che
contiene è illeggibile — per chi ti ruba il portatile, per chi legge il disco, e
per il servizio cloud che sincronizza la cartella.

Tutto avviene sul tuo computer. Non esiste un account CryptoVault, non esiste un
nostro server, non c'è telemetria. L'unica volta in cui l'applicazione usa la
rete è quando sei tu a chiederle di controllare gli aggiornamenti.

## Che cosa CryptoVault non è

- **Non è uno strumento di backup.** Un vault protegge la riservatezza dei tuoi
  file, non la loro esistenza. Se il disco muore, il vault muore con lui. Fanne
  una copia — copiare la cartella del vault è un backup valido, e resta cifrato.
- **Non è una protezione contro un computer compromesso.** Se sulla tua macchina
  gira già qualcosa di malevolo, può leggere i file mentre il vault è aperto e
  può registrare la password mentre la digiti. Nessuna applicazione può
  impedirlo.
- **Non è la cifratura dell'intero disco.** FileVault e BitLocker proteggono
  tutta la macchina quando è spenta. CryptoVault protegge un insieme preciso di
  file, sempre, anche dentro una cartella che sincronizzi sul cloud. Si
  completano a vicenda; nessuno dei due sostituisce l'altro.
- **Non è un gestore di password.** Puoi tenere dei segreti in un vault, ma un
  gestore di password dedicato fa quel lavoro meglio.

## I concetti

**Vault** — una cartella di file cifrati. Nomi, contenuti e struttura delle
cartelle sono tutti cifrati. Puoi averne più di uno, ognuno con la sua password.

**Password principale** — è ciò che sblocca un vault. Non viene salvata da
nessuna parte, e non può essere recuperata né reimpostata. Leggi il capitolo 11,
"Se perdi la password" (non ancora scritto), **prima** di creare il tuo primo
vault, non dopo.

**Bloccato e sbloccato** — un vault bloccato è illeggibile, anche per
CryptoVault. Lo sblocco ricava la chiave dalla tua password, e ci mette circa un
secondo apposta: è lo stesso secondo che un attaccante deve spendere per ogni
password che prova. Un vault si richiude da solo quando ti allontani, quando il
computer va in sospensione, o nell'istante in cui premi la scorciatoia di blocco.

**Sessione** — quando apri un file con un'altra applicazione, per esempio un
documento Word, CryptoVault ne decifra una copia temporanea, la consegna a Word
e la ri-cifra quando hai finito. Quella copia esiste, non cifrata, per tutto il
tempo in cui il file resta aperto. Il capitolo 6, "Aprire i file con altre
applicazioni" (non ancora scritto), spiega che cosa significa e che cosa no.

**Vault sigillato** — un vault creato con l'impostazione più severa. I file non
si possono trascinare fuori, esportare in chiaro né aprire con altre
applicazioni: li consulti dentro CryptoVault e li condividi solo in forma
cifrata. Adatto ai documenti su cui sei più prudente.

## Prima di cominciare

Tre cose da sapere prima del primo vault, in ordine di quanti guai causano
quando le si impara tardi:

1. **Perdere la password significa perdere i file.** Non c'è una porta di
   servizio, non c'è un indirizzo di assistenza che possa aiutarti, non c'è un
   reset. È il senso stesso di questo strumento, ed è anche il modo più comune
   in cui le persone perdono dati con software di questo tipo.
2. **Un vault vale quanto la sua password.** Tutta la crittografia di questo
   progetto serve a rendere costoso un tentativo; nessuna di essa può salvare
   una password indovinata al quarto colpo. Usa una frase lunga che non puoi
   dimenticare, oppure un gestore di password.
3. **La cifratura nasconde i tuoi file, non il fatto che tu li abbia.** Chi vede
   la cartella del vault può capire quanti file contiene, quanto sono grandi
   all'incirca e quando li hai modificati l'ultima volta. Il capitolo 12, "Da
   che cosa CryptoVault non protegge", ne conterrà l'elenco completo, e vale la
   pena leggerlo una volta.
