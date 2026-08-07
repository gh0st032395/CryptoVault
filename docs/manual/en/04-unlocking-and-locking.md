# 4. Unlocking and locking

> **CryptoVault is at milestone M3.** Everything in this chapter works.

Locked is the normal state. A vault spends most of its life shut, and the whole
design is arranged so that shut is also the safe state: while a vault is locked,
CryptoVault itself cannot read it any more than anyone else can.

## The list of vaults

The first screen is the vaults you have, each with its state written twice — as
a padlock and as a word — because the one fact you must not get wrong is whether
something is open.

Amber and **Locked**: unreadable. Green and **Unlocked**: open, and readable by
anything running as you.

The list is remembered between runs. What is never remembered is which vaults
were *open*: every start begins with everything shut, because a program that
reopened your vault on its own would be a program that opened it without a
password.

## Unlocking

Choose a vault, type the password, press **Unlock**.

It takes about a second, and the wait is the feature — see chapter 3. If it feels
slow, that is a second an attacker pays on every attempt they make.

**A wrong password** says so and lets you try again. It cannot tell you which
part was wrong, and it will never lock you out or count attempts: there is
nothing to lock, because there is no account, and an attacker with a copy of
your vault folder would not be asking this window anyway.

## Locking

Four ways, and they all do the same thing: the keys are wiped from memory and
the vault becomes unreadable again immediately.

**Lock now**, in the browser's toolbar. It sits alone at the right, away from
everything else, because it is the one control you may need to hit in a hurry.

**The tray**, in the menu bar or notification area. **Lock every vault** shuts
all of them at once, and it is there so you do not have to find the window
first. Use it when someone walks in.

**Auto-lock**, after fifteen idle minutes. Three policies, in Settings:

| Setting | What happens |
|---|---|
| **Warn, then lock** | A one-minute countdown you can stop. The default. |
| **Lock at once** | No countdown. Safest, and it will occasionally interrupt you. |
| **Only when I ask** | The timer is off. |

"Only when I ask" is a legitimate thing to want and it is also the exact failure
auto-lock exists to prevent: a vault left open stays open, including all night.
The application will not talk you out of it, but it will not pretend the three
are interchangeable either.

**Quitting.** Closing the window ends the application, which drops every key. A
vault is never left open by a program that is no longer running.

### What locking does not do

It does not touch your files, and it does not undo anything. A locked vault is
the same bytes on disk as an unlocked one — what changes is whether the key to
read them exists anywhere in memory.

It also cannot reach a copy that has already left the vault. If you extracted a
file to your desktop, locking does not remove it.

## Managing more than one vault

**Add an existing vault** points CryptoVault at a vault folder you already have
— one from another machine, or from a backup, or one you removed from the list
earlier. Choose the folder itself, the one containing `vault.cvconf`. The
folder's own name becomes the vault's name in the list.

**Removing one from the list** — the small × at the right of a row — takes it
out of the list and touches nothing on disk. The folder, and every file in it,
stays exactly where it is; you can add it again at any time. It asks first, and
says which vault, because "stop showing me this" and "delete my files" must
never be the same button.

There is no way to delete a vault from inside CryptoVault. Deleting the folder
in your file manager is how, and it is deliberate that you have to leave the
application to do it.

## If a vault will not open

- **Wrong password** is what it usually is. Check the keyboard layout and the
  caps lock, and try the passphrase you would have chosen at the time.
- **The folder has moved.** CryptoVault remembers a path, not the vault itself.
  Remove the entry from the list and add it again from its new location.
- **The drive is not there.** A vault on an external disk or a cloud folder that
  has not finished syncing will not open until it is present. The list keeps
  showing it, on purpose: a vault on an unplugged disk has not stopped existing.
