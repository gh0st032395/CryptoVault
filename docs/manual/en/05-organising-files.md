# 5. Organising your files

> **CryptoVault is at milestone M3.** You can make folders, rename things and
> delete them. **Getting files into a vault, and back out, is the next
> milestone** — the *Add files* and *Extract* buttons are visible and disabled,
> and their tooltips say so. This chapter will grow when they work.

## The browser

An unlocked vault opens on two panes. The **folder tree** on the left is the
shape of the vault; the **list** on the right is what is in the folder you have
chosen. They stay in step: walk into a folder in the list and the tree opens to
show where you are.

The **breadcrumbs** along the top are the path back out — every step is a button.

The folder button at the far left of the toolbar hides and shows the tree, and
remembers which you chose. On a narrow window you will want it off.

The tree reads a folder only when you open it, which is why a folder you have
never expanded shows an arrow even when it turns out to be empty: finding out
would mean reading it, and reading every folder to draw a sidebar would be the
slowest thing the application does.

## Sorting and finding

Click **Name**, **Size** or **Modified** to sort by that column; click the same
one again to reverse it. Folders stay first either way — reversing the order
turns the list over, it does not shuffle folders in among the files.

**Search** filters the folder you are looking at, by name, as you type. It is not
a search of the whole vault: that arrives with the search index in a later
milestone. Clearing the box, or moving to another folder, restores the full list.

Sizes are the real, plaintext size of each file. Folders show `—` rather than a
total, because adding one up would mean opening every file inside it.

## Making, renaming and deleting

**New folder** makes one inside the folder you are looking at. Names are
encrypted, so you are not bound by what your operating system allows: `report:
Q1*.txt`, a name ending in a dot, `CON` — all fine inside a vault, all of them
things Windows would refuse on a normal disk.

**Rename** works on one selected item. The extension is left out of the initial
selection, because changing the name is the common case and deleting `.pdf` by
accident is not.

**Delete** removes the selection, and everything inside it if it is a folder. It
asks first, names what it is about to remove, and says the part that matters:

> **there is no trash yet.** A deleted file is not recoverable from the vault.

That is true and worth taking literally. The trash arrives in a later milestone;
until it does, delete means gone.

To select more than one thing, hold **⌘** (macOS) or **Ctrl** and click.

## Two limits worth knowing now

**Renaming a folder does not move what is inside it.** The folder keeps its
identity and its contents; only the name changes. This is a property of how the
vault stores directories, and it is the behaviour you want — renaming a folder
of ten thousand files does not rewrite ten thousand files.

**A folder with very many files is fine.** The list only draws the rows you can
see, so a folder holding tens of thousands of entries scrolls at the same speed
as one holding six. Opening it still takes a moment, because the vault reads
each entry to report its size.
