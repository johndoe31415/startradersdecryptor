# startradersdecryptor
This is a decryptor for savegames of the game [Star Traders:
Frontiers](https://store.steampowered.com/app/335620/Star_Traders_Frontiers/).
I was intrigued by the fact that savegames look like they're encrypted
perfectly; most games use really crappy encryption. So for the purpose of
finding out, I dug into this and found out the algorithms they're using to
encrypt savegames as a fun exercise.

## Security
Savegames of Star Traders: Frontiers are Sqlite3 databases which are encrypted
using Twofish256 in XTS mode (i.e., 512 bit keys). Segmentation of the database
is done on a Sqlite page basis (chunks of 1024 bytes), making XTS an
appropriate operation mode for this purpose. The keys are static; internally,
PBKDF2-SHA1 is used to derive them also with static passphrase and salt values.
The salt is always the same, the passphrase differs for the at least four
distinct keys for different database types (core/data/game/map files). The
purpose of key derivation is not exactly clear, considering that the derived
key is always the same for a particular file type.

Apart from the encrpytion key, a 128-bit "master nonce key" is derived as well.
This is used to key CMAC-Twofish and for every page, the little-endian 32-bit
page number is CMACed to get the page nonce. This is completely unnecessary in
my opinion, since the idea behind XTS is that the page number can be directly
used as a tile nonce. So I'm unsure why this additional layer of obfuscation
was introduced, but it certainly doesn't harm security (nor does it make
reversing significantly harder).

All-in-all some quite good encryption for just a computer game. However, with
keys stored statically of course the best encryption is just obfuscation,
because the keys naturally need to be stored within the binary itself. But it
certainly deters many people from tampering with the savegame.

## Usage
Usage is shown when the program is invoked without parameters:

```
$ ./startradersdecryptor
./startradersdecryptor [keyname] [infile] [outfile]
   keyname can be one of 'core', 'data', 'game' or 'map'.
   example: ./startradersdecryptor core ~/.config/startraders2/core.db core_decrypted.db
```

And is actually really simple, as shown:

```
$ ./startradersdecryptor core ~/.config/startraders2/core.db core_decrypted.db
Read 12288 bytes.
XTS key     : 970965909D21E6A5E37AA83214E15F297CFBFAD275F9320BFC4AE1D7EDD5C4EC7CF5A87202ED16C018777ED604A74CFEF1AFC1E6DCB7596CCB3E50D212ED30CE
CMAC key    : 725532A4BF714416BD0F104722CF044A

$ ./startradersdecryptor game ~/.config/startraders2/game_2.db game_decrypted.db
Read 190464 bytes.
XTS key     : 073D0CF41A8BAF2A3A431A0998CEA4F7F238971E15C457721E438227A9561691B2069B64CDAC28E57F6D9C28E63CBF5E05D951E6CE7B0B2E61FFEE3E9F4947B9
CMAC key    : F8EAC06133971F6E760545C628F06A1C
```

Note that the reverse operation, i.e., re-encoding a tampered savegame into a
format that Star Traders: Frontiers can use, is absolutely trivial when looking
at the source code, but I have not implemented it.

## License
GNU GPL-3.
