# 5. Organizzare i file

> **CryptoVault è alla milestone M3.** Puoi creare cartelle, rinominare ed
> eliminare. **Portare i file dentro un vault, e farli uscire, è la milestone
> successiva**: i pulsanti *Aggiungi file* ed *Estrai* sono visibili e
> disattivati, e i loro suggerimenti lo dicono. Questo capitolo crescerà quando
> funzioneranno.

## Il browser

Un vault sbloccato si apre su due riquadri. L'**albero delle cartelle** a
sinistra è la forma del vault; l'**elenco** a destra è quello che contiene la
cartella che hai scelto. Restano allineati: entra in una cartella dall'elenco e
l'albero si apre per mostrarti dove sei.

Le **briciole di pane** in alto sono la strada per tornare indietro: ogni passo
è un pulsante.

Il pulsante con la cartella all'estrema sinistra della barra mostra e nasconde
l'albero, e ricorda la tua scelta. Con una finestra stretta lo vorrai spento.

L'albero legge una cartella solo quando la apri: per questo una cartella che non
hai mai espanso mostra una freccia anche se poi risulta vuota. Scoprirlo
vorrebbe dire leggerla, e leggere ogni cartella per disegnare una barra laterale
sarebbe la cosa più lenta che l'applicazione fa.

## Ordinare e trovare

Clicca **Nome**, **Dimensione** o **Modificato** per ordinare secondo quella
colonna; clicca di nuovo sulla stessa per invertire l'ordine. Le cartelle
restano comunque in cima: invertire capovolge l'elenco, non mescola le cartelle
in mezzo ai file.

**Cerca** filtra per nome la cartella che stai guardando, mentre digiti. Non è
una ricerca su tutto il vault: quella arriva con l'indice di ricerca in una
milestone successiva. Svuotare il campo, o spostarsi in un'altra cartella,
ripristina l'elenco completo.

Le dimensioni sono quelle reali, in chiaro, di ogni file. Le cartelle mostrano
`—` invece di un totale, perché sommarlo vorrebbe dire aprire ogni file che
contengono.

## Creare, rinominare, eliminare

**Nuova cartella** la crea dentro la cartella che stai guardando. I nomi sono
cifrati, quindi non sei vincolato a quello che il tuo sistema operativo
permette: `report: Q1*.txt`, un nome che finisce con un punto, `CON` — dentro un
vault vanno tutti bene, e sono tutte cose che Windows rifiuterebbe su un disco
normale.

**Rinomina** agisce su un solo elemento selezionato. L'estensione resta fuori
dalla selezione iniziale, perché cambiare il nome è il caso comune e cancellare
`.pdf` per sbaglio no.

**Elimina** rimuove la selezione, e tutto quello che contiene se è una cartella.
Chiede conferma, nomina quello che sta per rimuovere, e dice la parte che conta:

> **il cestino non c'è ancora.** Un file eliminato non è più recuperabile dal
> vault.

È vero e va preso alla lettera. Il cestino arriva in una milestone successiva;
finché non arriva, eliminare vuol dire perso.

Per selezionare più di un elemento, tieni premuto **⌘** (macOS) o **Ctrl** e
clicca.

## Due limiti che vale la pena conoscere subito

**Rinominare una cartella non sposta quello che contiene.** La cartella mantiene
la sua identità e il suo contenuto; cambia solo il nome. È una proprietà di come
il vault memorizza le directory, ed è il comportamento che vuoi: rinominare una
cartella con diecimila file non riscrive diecimila file.

**Una cartella con moltissimi file non è un problema.** L'elenco disegna solo le
righe che puoi vedere, quindi una cartella con decine di migliaia di voci scorre
alla stessa velocità di una che ne ha sei. Aprirla richiede comunque un momento,
perché il vault legge ogni voce per riportarne la dimensione.
