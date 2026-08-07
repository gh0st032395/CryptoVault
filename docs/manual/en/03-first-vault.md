# 3. Creating your first vault

> **CryptoVault is at milestone M3.** The application runs, creates vaults and
> opens them. Getting files *into* a vault from your disk is the next milestone,
> so a vault you make today is somewhere to keep folders rather than files. Do
> not move anything you care about into one yet.

A vault is a folder. Everything inside it is encrypted — the contents of the
files, their names, and the shape of the folders they sit in. You choose where
that folder lives and what it is called, and from then on you unlock it with a
password.

## Making one

Press **Create a vault**. Four things to decide, and only one of them is hard.

**A name.** What you will call it in the list of vaults. It is not encrypted:
it is stored by the application, not in the vault, and it is there so you can
tell two vaults apart.

**A location.** Press **Choose…** and pick the folder you want the vault to sit
in. CryptoVault makes a new folder inside it, named after the vault, and shows
you the full path before you commit. A vault on an external disk or inside a
Dropbox or iCloud folder is fine and is a thing this tool is built for.

**A password.** This is the hard one, and the rest of this chapter is about it.

**Whether it is sealed.** Leave this off unless you know you want it — see
below.

## The password

There is no way to recover it. Not by us, not by anyone. There is no reset link,
no support address, no back door, and no second copy of your key held anywhere.
If you forget the password, the vault is a folder of noise and stays that way.

This is the point of the tool. It is also, by a wide margin, the most common way
people lose data with software of this kind — not to attackers, but to their own
memory. Treat it as the decision it is:

- Use a **long passphrase** you cannot forget — several unrelated words — or a
  **password manager**, which is the better answer if you already have one.
- Do not use a password you use elsewhere. If it appears in a breach somewhere
  else, it becomes the first thing tried here.
- Write it down and put it somewhere safe if that is what it takes. A passphrase
  on paper in a drawer is a real risk you have chosen; a passphrase you cannot
  remember is a certainty.

### The strength meter

The bar under the password field is a rough estimate from length and variety,
and it is honest about being no more than that. It cannot tell whether your
password is *guessable*: `Password123!` scores well and is on every list an
attacker owns. A long ordinary sentence will score lower and be far stronger.

Take a poor score as a warning and a good score as nothing at all.

### Why unlocking is slow

Deliberately, and it matters here rather than later: CryptoVault spends about a
second turning your password into a key. That second is the same second an
attacker has to spend on every password they try. It is what turns a guessing
rate of millions per second into a few per second, and it is the difference
between a decent passphrase being safe and being merely inconvenient.

The application measures your machine when it creates the vault and picks
settings that cost about a second *there*, so a vault made on a fast computer is
harder to attack than one made on a slow one. Those settings are stored in the
vault, so it still opens on any machine.

## Sealed vaults

A sealed vault refuses to let files out in readable form: they cannot be
extracted in the clear or opened in other applications. You look at them inside
CryptoVault and share them only encrypted.

Two things to understand before choosing it:

- It is a **rule this application enforces**, not something the cryptography
  makes impossible. Anyone with the password can get the data out another way.
  It protects against habit and haste, not against a determined person.
- You choose it when you create the vault. Treat it as permanent.

It suits the small set of documents you are most careful about, and gets in the
way everywhere else. Most people want it off.

## What happens next

The vault is created and **left locked**. That is deliberate: creating a vault is
not a way into an open one, and typing the password once more straight away is
the cheapest possible check that you typed what you meant to the first time.

If the second attempt does not work, you have found out now — while the vault is
empty — rather than in six months.

Look in the folder you chose and you will find a new folder with the vault's
name in it, holding a `vault.cvconf` file and a `d` directory. That is the whole
vault. Copying that folder copies the vault, encrypted; deleting it deletes the
vault, and nothing else knows how to bring it back.

## Where the list of vaults is kept

CryptoVault remembers which vaults you have and where they are, so it does not
ask you to find them again every morning. That list lives with the application,
not with the vaults:

| System | Location |
|---|---|
| macOS | `~/Library/Application Support/app.cryptovault.desktop/` |
| Windows | `%APPDATA%\app.cryptovault.desktop\` |
| Linux | `~/.config/app.cryptovault.desktop/` |

It holds names and paths, and nothing else — no keys, and no record of which
vault was open. Deleting it loses the list, never a vault: point CryptoVault at
the folders again with **Add an existing vault** and everything comes back.
