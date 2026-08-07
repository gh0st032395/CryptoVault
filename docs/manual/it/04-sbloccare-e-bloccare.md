# 4. Sbloccare e bloccare

> **CryptoVault è alla milestone M3.** Tutto quello che c'è in questo capitolo
> funziona.

Bloccato è lo stato normale. Un vault passa quasi tutta la sua vita chiuso, e
l'intero progetto è fatto perché chiuso sia anche lo stato sicuro: finché un
vault è bloccato, CryptoVault stesso non riesce a leggerlo più di chiunque
altro.

## L'elenco dei vault

La prima schermata sono i vault che hai, ognuno con il suo stato scritto due
volte — come lucchetto e come parola — perché l'unica cosa che non devi
sbagliare è capire se qualcosa è aperto.

Ambra e **Bloccato**: illeggibile. Verde e **Sbloccato**: aperto, e leggibile da
qualunque cosa giri con la tua utenza.

L'elenco viene ricordato fra un avvio e l'altro. Quello che non viene *mai*
ricordato è quali vault erano aperti: ogni avvio parte con tutto chiuso, perché
un programma che ti riapre il vault da solo sarebbe un programma che lo apre
senza password.

## Sbloccare

Scegli un vault, digita la password, premi **Sblocca**.

Ci mette circa un secondo, e l'attesa è la funzione — vedi il capitolo 3. Se ti
sembra lento, è un secondo che un attaccante paga a ogni tentativo.

**Una password sbagliata** te lo dice e ti lascia riprovare. Non può dirti quale
parte era sbagliata, e non ti bloccherà mai fuori né conterà i tentativi: non
c'è niente da bloccare, perché non esiste un account, e un attaccante con una
copia della cartella del vault non starebbe comunque chiedendo a questa
finestra.

## Bloccare

Quattro modi, e fanno tutti la stessa cosa: le chiavi vengono cancellate dalla
memoria e il vault torna illeggibile all'istante.

**Blocca ora**, nella barra del browser. Sta da solo a destra, lontano da tutto
il resto, perché è il comando che potresti dover premere di fretta.

**Il tray**, nella barra dei menu o nell'area di notifica. **Blocca tutti i
vault** li chiude tutti insieme, ed è lì perché tu non debba prima ritrovare la
finestra. Usalo quando entra qualcuno.

**Il blocco automatico**, dopo quindici minuti di inattività. Tre politiche,
nelle Impostazioni:

| Impostazione | Che cosa fa |
|---|---|
| **Avvisa, poi blocca** | Un conto alla rovescia di un minuto che puoi fermare. È il default. |
| **Blocca subito** | Nessun conto alla rovescia. Il più sicuro, e ogni tanto ti interromperà. |
| **Solo quando lo chiedo** | Il timer è spento. |

«Solo quando lo chiedo» è una cosa legittima da volere ed è anche esattamente il
guasto da cui il blocco automatico dovrebbe proteggere: un vault lasciato aperto
resta aperto, anche tutta la notte. L'applicazione non proverà a dissuaderti, ma
non farà nemmeno finta che le tre opzioni siano intercambiabili.

**Uscire.** Chiudere la finestra termina l'applicazione, e questo elimina ogni
chiave. Un vault non resta mai aperto per colpa di un programma che non è più in
esecuzione.

### Che cosa il blocco non fa

Non tocca i tuoi file e non annulla niente. Un vault bloccato è la stessa
sequenza di byte su disco di uno sbloccato: quello che cambia è se la chiave per
leggerli esiste da qualche parte in memoria.

E non può raggiungere una copia che è già uscita dal vault. Se hai estratto un
file sulla scrivania, bloccare non lo rimuove.

## Gestire più di un vault

**Aggiungi un vault esistente** indica a CryptoVault una cartella-vault che hai
già: una da un'altra macchina, da un backup, o una che avevi tolto dall'elenco.
Scegli la cartella stessa, quella che contiene `vault.cvconf`. Il nome della
cartella diventa il nome del vault nell'elenco.

**Toglierne uno dall'elenco** — la piccola × a destra della riga — lo rimuove
dall'elenco e non tocca niente su disco. La cartella, e ogni file dentro,
restano esattamente dove sono; puoi riaggiungerla quando vuoi. Chiede conferma,
e dice di quale vault si tratta, perché «smetti di mostrarmi questo» e «cancella
i miei file» non devono mai essere lo stesso pulsante.

Non c'è modo di cancellare un vault da dentro CryptoVault. Si fa eliminando la
cartella dal gestore di file, ed è voluto che tu debba uscire dall'applicazione
per farlo.

## Se un vault non si apre

- **La password sbagliata** è quasi sempre la causa. Controlla la disposizione
  della tastiera e il blocco maiuscole, e prova la frase che avresti scelto
  all'epoca.
- **La cartella è stata spostata.** CryptoVault ricorda un percorso, non il
  vault. Togli la voce dall'elenco e riaggiungila dalla nuova posizione.
- **Il disco non c'è.** Un vault su un disco esterno o in una cartella cloud che
  non ha finito di sincronizzare non si apre finché non è presente. L'elenco
  continua a mostrarlo, di proposito: un vault su un disco scollegato non ha
  smesso di esistere.
