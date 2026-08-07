/**
 * Italian and English, side by side.
 *
 * Every string lives here with both translations next to each other, rather
 * than in two files that drift apart. The type of `Dictionary` is derived from
 * the English text, so a missing Italian string is a compile error rather than
 * something a user discovers.
 */

export type Language = 'it' | 'en';

const en = {
  appName: 'CryptoVault',

  // Vault list
  yourVaults: 'Your vaults',
  noVaultsYet: 'No vaults yet',
  noVaultsBody:
    'A vault is a folder whose contents are encrypted. Create one, and everything you put inside is unreadable until you unlock it.',
  createVault: 'Create a vault',
  addExisting: 'Add an existing vault',
  locked: 'Locked',
  unlocked: 'Unlocked',
  forget: 'Remove from the list',
  forgetConfirm: 'Remove this vault from the list? The folder and everything in it stay where they are.',

  // Unlock
  unlock: 'Unlock',
  unlocking: 'Unlocking…',
  password: 'Password',
  wrongPassword: 'That password does not open this vault.',
  unlockHint: 'Unlocking takes about a second on purpose — see the tooltip.',

  // Create
  newVault: 'New vault',
  vaultName: 'Name',
  vaultLocation: 'Location',
  locationPlaceholder: 'Choose a folder to put it in',
  choose: 'Choose…',
  confirmPassword: 'Repeat the password',
  passwordsDiffer: 'The two passwords are not the same.',
  sealedVault: 'Sealed vault',
  sealedExplain: 'Files may not leave this vault in readable form.',
  createWarningTitle: 'There is no way to recover this password',
  createWarningBody:
    'If you forget it, the vault is gone. That is the point of the tool, and it is the most common way people lose data with software like this. Use a long passphrase you cannot forget, or a password manager.',
  create: 'Create',
  cancel: 'Cancel',

  // Password strength
  strengthWeak: 'Weak',
  strengthFair: 'Fair',
  strengthGood: 'Good',
  strengthStrong: 'Strong',

  // Browser
  search: 'Search',
  newFolder: 'New folder',
  addFiles: 'Add files',
  extract: 'Extract',
  rename: 'Rename',
  remove: 'Remove',
  lockNow: 'Lock now',
  emptyFolder: 'This folder is empty',
  emptyFolderBody: 'Drag files here, or use “Add files”.',
  nameColumn: 'Name',
  sizeColumn: 'Size',
  modifiedColumn: 'Modified',
  itemsSelected: 'selected',
  folders: 'Folders',
  vaultRoot: 'All files',
  expand: 'Show what is inside',
  collapse: 'Hide what is inside',
  removeTitle: 'Delete permanently?',
  removeBody:
    'this cannot be undone. There is no trash yet, and a deleted file is not recoverable from the vault.',

  // Auto-lock
  autoLockTitle: 'Locking in',
  autoLockBody: 'You have been away. The vault is about to lock.',
  stayUnlocked: 'Stay unlocked',
  lockNowShort: 'Lock',

  // Settings
  settings: 'Settings',
  autoLock: 'Auto-lock',
  policyWarn: 'Warn, then lock',
  policyImmediate: 'Lock at once',
  policyManual: 'Only when I ask',
  theme: 'Appearance',
  themeLight: 'Light',
  themeDark: 'Dark',
  themeSystem: 'System',
  language: 'Language',

  // Tooltips. Every button has one; this is where the explaining happens.
  tipUnlock: 'Derive the key from your password and open the vault.',
  tipUnlockSlow:
    'This takes about a second, deliberately: it is the same second an attacker must spend on every password they try.',
  tipCreateVault: 'Make a new encrypted folder. You choose where it lives.',
  tipAddExisting: 'Point CryptoVault at a vault folder you already have.',
  tipLockNow:
    'Wipe the keys from memory. Everything becomes unreadable again immediately.',
  tipNewFolder: 'Create a folder inside the vault. Its name is encrypted too.',
  tipAddFiles: 'Copy files into the vault. The originals are not touched.',
  tipAddFilesSoon:
    'Not built yet. Copying files in needs a progress bar and a way to stop it partway, which is the next milestone.',
  tipExtract:
    'Copy the selection out of the vault. Warning: the copy is not encrypted.',
  tipExtractSoon:
    'Not built yet. Writing files back out in readable form needs progress, cancellation, and the warning that goes with it.',
  tipTree: 'Show or hide the folder list beside the files. Useful on a narrow window.',
  tipSortName: 'Sort by name. Click again to reverse it. Folders stay first either way.',
  tipSortSize: 'Sort by size, largest first. Folders have no size of their own here.',
  tipSortModified:
    'Sort by the time the file was last changed, newest first. Files with no recorded time sort last.',
  tipRename: 'Change the name. Renaming a folder does not move what is inside it.',
  tipRemove: 'Delete permanently. There is no trash yet.',
  tipSearch: 'Filter by name within this folder.',
  tipTheme: 'Light, dark, or whatever the system is set to.',
  tipPolicyWarn:
    'After fifteen idle minutes, a one-minute countdown you can stop. If nobody stops it, the vault locks anyway.',
  tipPolicyImmediate:
    'After fifteen idle minutes, lock with no warning. Safest, and it will occasionally interrupt you.',
  tipPolicyManual:
    'Never lock on its own. A vault left open stays open — including all night, which is the exact thing auto-lock exists to prevent.',
  tipLanguage: 'Interface language.',
  tipSealed:
    'A sealed vault refuses to let files out in readable form. Note it is a rule this application enforces, not something the cryptography prevents: anyone with the password can still extract the data another way.',
  tipStrength:
    'An estimate from length and variety. It cannot judge whether your password is guessable — “Password123!” scores well and is not.',
  tipVaultPath: 'Where the encrypted folder lives on your disk.',
  tipForget:
    'Take this vault out of the list. Nothing is deleted — the folder stays exactly where it is, and you can add it again at any time.',

  // Statuses and warnings
  notEncryptedWarning: 'The extracted copy is not encrypted.',
  demoBanner:
    'Demonstration data, running in a browser. Nothing here is a real vault; the password is',
  couldNotRead: 'This folder could not be read.',
} as const;

/** Every string the interface can show. Derived from English, so nothing drifts. */
export type Dictionary = { readonly [K in keyof typeof en]: string };

const it: Dictionary = {
  appName: 'CryptoVault',

  yourVaults: 'I tuoi vault',
  noVaultsYet: 'Nessun vault',
  noVaultsBody:
    'Un vault è una cartella il cui contenuto è cifrato. Creane uno: tutto quello che ci metti dentro resta illeggibile finché non lo sblocchi.',
  createVault: 'Crea un vault',
  addExisting: 'Aggiungi un vault esistente',
  locked: 'Bloccato',
  unlocked: 'Sbloccato',
  forget: 'Togli dall’elenco',
  forgetConfirm:
    'Vuoi togliere questo vault dall’elenco? La cartella e tutto quello che contiene restano dove sono.',

  unlock: 'Sblocca',
  unlocking: 'Sblocco in corso…',
  password: 'Password',
  wrongPassword: 'Questa password non apre il vault.',
  unlockHint: 'Lo sblocco richiede circa un secondo, apposta — vedi il suggerimento.',

  newVault: 'Nuovo vault',
  vaultName: 'Nome',
  vaultLocation: 'Posizione',
  locationPlaceholder: 'Scegli la cartella in cui metterlo',
  choose: 'Scegli…',
  confirmPassword: 'Ripeti la password',
  passwordsDiffer: 'Le due password non coincidono.',
  sealedVault: 'Vault sigillato',
  sealedExplain: 'I file non possono uscire da questo vault in chiaro.',
  createWarningTitle: 'Questa password non è recuperabile',
  createWarningBody:
    'Se la dimentichi, il vault è perso. È il senso stesso di questo strumento, ed è il modo più comune in cui si perdono dati con software di questo tipo. Usa una frase lunga che non puoi dimenticare, oppure un gestore di password.',
  create: 'Crea',
  cancel: 'Annulla',

  strengthWeak: 'Debole',
  strengthFair: 'Discreta',
  strengthGood: 'Buona',
  strengthStrong: 'Forte',

  search: 'Cerca',
  newFolder: 'Nuova cartella',
  addFiles: 'Aggiungi file',
  extract: 'Estrai',
  rename: 'Rinomina',
  remove: 'Elimina',
  lockNow: 'Blocca ora',
  emptyFolder: 'Questa cartella è vuota',
  emptyFolderBody: 'Trascina qui i file, oppure usa «Aggiungi file».',
  nameColumn: 'Nome',
  sizeColumn: 'Dimensione',
  modifiedColumn: 'Modificato',
  itemsSelected: 'selezionati',
  folders: 'Cartelle',
  vaultRoot: 'Tutti i file',
  expand: 'Mostra il contenuto',
  collapse: 'Nascondi il contenuto',
  removeTitle: 'Eliminare definitivamente?',
  removeBody:
    'l’operazione non si può annullare. Il cestino non c’è ancora, e un file eliminato non è più recuperabile dal vault.',

  autoLockTitle: 'Blocco fra',
  autoLockBody: 'Sei stato via. Il vault sta per bloccarsi.',
  stayUnlocked: 'Resta sbloccato',
  lockNowShort: 'Blocca',

  settings: 'Impostazioni',
  autoLock: 'Blocco automatico',
  policyWarn: 'Avvisa, poi blocca',
  policyImmediate: 'Blocca subito',
  policyManual: 'Solo quando lo chiedo',
  theme: 'Aspetto',
  themeLight: 'Chiaro',
  themeDark: 'Scuro',
  themeSystem: 'Sistema',
  language: 'Lingua',

  tipUnlock: 'Ricava la chiave dalla password e apre il vault.',
  tipUnlockSlow:
    'Ci mette circa un secondo, di proposito: è lo stesso secondo che un attaccante deve spendere per ogni password che prova.',
  tipCreateVault: 'Crea una nuova cartella cifrata. Scegli tu dove metterla.',
  tipAddExisting: 'Indica a CryptoVault una cartella-vault che hai già.',
  tipLockNow:
    'Cancella le chiavi dalla memoria. Tutto torna illeggibile all’istante.',
  tipNewFolder: 'Crea una cartella dentro il vault. Anche il suo nome è cifrato.',
  tipAddFiles: 'Copia dei file nel vault. Gli originali non vengono toccati.',
  tipAddFilesSoon:
    'Non c’è ancora. Copiare file dentro richiede una barra di avanzamento e un modo per fermarla a metà: è la prossima milestone.',
  tipExtract:
    'Copia la selezione fuori dal vault. Attenzione: la copia non è cifrata.',
  tipExtractSoon:
    'Non c’è ancora. Riscrivere i file in chiaro richiede avanzamento, annullamento e l’avviso che li accompagna.',
  tipTree:
    'Mostra o nasconde l’elenco delle cartelle accanto ai file. Utile con una finestra stretta.',
  tipSortName:
    'Ordina per nome. Un altro clic inverte l’ordine. Le cartelle restano comunque in cima.',
  tipSortSize:
    'Ordina per dimensione, prima le più grandi. Qui le cartelle non hanno una dimensione propria.',
  tipSortModified:
    'Ordina per data dell’ultima modifica, prima i più recenti. I file senza data finiscono in fondo.',
  tipRename:
    'Cambia il nome. Rinominare una cartella non sposta quello che contiene.',
  tipRemove: 'Elimina definitivamente. Il cestino non c’è ancora.',
  tipSearch: 'Filtra per nome dentro questa cartella.',
  tipTheme: 'Chiaro, scuro, o quello che dice il sistema.',
  tipPolicyWarn:
    'Dopo quindici minuti di inattività, un conto alla rovescia di un minuto che puoi fermare. Se nessuno lo ferma, il vault si blocca comunque.',
  tipPolicyImmediate:
    'Dopo quindici minuti di inattività, blocca senza avvisare. Il più sicuro, e ogni tanto ti interromperà.',
  tipPolicyManual:
    'Non si blocca mai da solo. Un vault lasciato aperto resta aperto — anche tutta la notte, che è esattamente ciò da cui il blocco automatico dovrebbe proteggere.',
  tipLanguage: 'Lingua dell’interfaccia.',
  tipSealed:
    'Un vault sigillato non lascia uscire i file in chiaro. Nota che è una regola applicata da questo programma, non qualcosa che la crittografia impedisce: chi ha la password può comunque estrarre i dati in altro modo.',
  tipStrength:
    'Una stima basata su lunghezza e varietà. Non può giudicare se la password è indovinabile: «Password123!» prende un buon punteggio e non lo è.',
  tipVaultPath: 'Dove si trova la cartella cifrata sul tuo disco.',
  tipForget:
    'Toglie questo vault dall’elenco. Non cancella nulla: la cartella resta esattamente dov’è, e puoi riaggiungerla quando vuoi.',

  notEncryptedWarning: 'La copia estratta non è cifrata.',
  demoBanner:
    'Dati dimostrativi, in un browser. Niente di quello che vedi è un vault reale; la password è',
  couldNotRead: 'Non è stato possibile leggere questa cartella.',
};

const dictionaries: Record<Language, Dictionary> = { en, it };

/** Picks a starting language from the system, defaulting to English. */
export function detectLanguage(): Language {
  return navigator.language?.toLowerCase().startsWith('it') ? 'it' : 'en';
}

/** The strings for a language. */
export function strings(language: Language): Dictionary {
  return dictionaries[language];
}
