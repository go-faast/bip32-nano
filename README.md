# bip32-nano

A [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) compatible library for the Nano currency written in TypeScript with transpiled JavaScript committed to git. Based on the implementation by [superdarkbit](https://github.com/superdarkbit/nano-bip32-ed25519) which is based on this [BIP32-ED25519 spec](https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view).

This library attempts to conform the the `BIP32Interface` defined by the [bitcoinjs bip32](https://github.com/bitcoinjs/bip32) library.

The following are intentional deviations or incompatabilities:

- `BIP32Interface.toWIF` is not supported because Nano does not use WIF for private keys
- xprv's are 109 bytes instead of the standard 78 bytes in order to include the full 512 bit private key that is needed for BIP32-ED25519
- xpub'b are 77 bytes instead of the standard 78 bytes because byte 45 is no longer needed to indicate whether the public key is compressed. ED25519 public keys are always compressed.
- BIP32-ED25519 requires a master secret such that it's SHA512 hash has the third highest bit of the first 32 bytes unset. In order to be compatible with all existing seeds, a conforming master secret is discovered by iterating over 32 bit integers `i` starting from 0 until `SHA512(i, seed)` meets the requirements.

## Example

TypeScript

``` typescript
import * as bip32 from 'bip32-nano';
import { BIP32Interface } from 'bip32-nano';
let node: BIP32Interface = bip32.fromBase58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi');

let child: BIP32Interface = node.derivePath('m/0/0');
// ...
```

NodeJS

``` javascript
let bip32 = require('bip32-nano')
let node = bip32.fromBase58('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi')

let child = node.derivePath('m/0/0')
// ...
```

## LICENSE [MIT](LICENSE)
