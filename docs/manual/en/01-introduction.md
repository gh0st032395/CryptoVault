# 1. Introduction

> **CryptoVault is not finished.** At the time of writing the project is at
> milestone M3: the application runs, and it creates, opens and browses vaults.
> What it cannot do yet is bring files in from your disk or write them back
> out, which arrives with M4. Do not store anything you care about in a
> CryptoVault vault yet.

## What CryptoVault is

CryptoVault creates **vaults**: encrypted areas on your disk where files stay
usable. You unlock a vault with a password, browse your files, open them, change
them, and lock it again. While the vault is locked, everything inside it is
unreadable — to anyone who takes your laptop, to anyone who reads the disk, and
to the cloud provider syncing the folder.

Everything happens on your computer. There is no CryptoVault account, no server
of ours, and no telemetry. The only time the application uses the network is
when you ask it to check for an update.

## What CryptoVault is not

- **It is not a backup tool.** A vault protects the confidentiality of your
  files, not their existence. If the disk dies, the vault dies with it. Back it
  up — a plain copy of the vault folder is a valid backup, and it stays
  encrypted.
- **It is not protection against a compromised computer.** If something
  malicious is already running on your machine, it can read your files while the
  vault is open and can record your password as you type it. No application can
  prevent that.
- **It is not full-disk encryption.** FileVault and BitLocker protect the whole
  machine when it is off. CryptoVault protects a specific set of files, all the
  time, including inside a folder you sync to the cloud. They complement each
  other; neither replaces the other.
- **It is not a password manager.** You can keep secrets in a vault, but a
  dedicated password manager does that job better.

## The concepts

**Vault** — a folder of encrypted files. Names, contents and folder structure
are all encrypted. You can have several, each with its own password.

**Master password** — what unlocks a vault. It is never stored anywhere, and it
cannot be recovered or reset. Read chapter 11, "Losing your password" (not written yet) before you
create your first vault, not after.

**Locked and unlocked** — a locked vault is unreadable, including to
CryptoVault. Unlocking derives the key from your password, which deliberately
takes about a second: the same second an attacker has to spend on every password
they try. A vault locks itself again when you have been away, when the computer
sleeps, or the moment you press the lock shortcut.

**Session** — when you open a file in another application, say a Word document,
CryptoVault decrypts a temporary copy, hands it to Word, and re-encrypts it when
you are done. That copy exists, unencrypted, for as long as the file is open.
Chapter 6, "Opening files in other applications" (not written yet), explains what that does and does not
mean.

**Sealed vault** — a vault created with the strictest setting. Files cannot be
dragged out, exported in the clear, or opened in other applications; you view
them inside CryptoVault, and share them only in encrypted form. Suited to the
documents you are most careful about.

## Before you start

Three things worth knowing before your first vault, in order of how much trouble
they cause when learned too late:

1. **Losing your password means losing your files.** There is no back door, no
   support address that can help, no reset. This is the point of the tool, and
   it is also the most common way people lose data with software of this kind.
2. **A vault is only as strong as its password.** All the cryptography in this
   project is arranged around making a guess expensive; none of it can save a
   password that is guessed on the fourth attempt. Use a long passphrase you
   cannot forget, or a password manager.
3. **Encryption hides your files, not the fact that you have them.** Someone who
   can see the vault folder can tell how many files it holds, roughly how big
   each one is, and when you last changed them.
   Chapter 12, "What CryptoVault does not protect against", will be the complete list, and it is worth reading once.
