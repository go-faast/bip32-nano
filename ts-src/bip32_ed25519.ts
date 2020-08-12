import jsSHA from 'jssha';
import * as crypto from 'crypto';
const blake = require('blakejs');
import * as ed25519 from './ed25519';
import { BigInteger, bi, zero, one, two, bytes2bi, bi2bytes, concatUint8Arrays } from './helpers.js';

type Node = [[Uint8Array, Uint8Array], Uint8Array, Uint8Array]
type PublicNode = [Uint8Array, Uint8Array]

// Adapted from:
// https://github.com/superdarkbit/nano-bip32-ed25519/blob/master/src/js/bip32_ed25519.js
// With patches from the Nano team

export function uint8ToHex(uintValue: Uint8Array) {
    let hex = '';
    let aux;
    for (let value of uintValue) {
        aux = value.toString(16).toLowerCase();
        if (aux.length === 1)
            aux = '0' + aux;
        hex += aux;
        aux = '';
    }

    return hex;
}

export function hexToUint8(hexValue: string) {
    let length = (hexValue.length / 2) | 0;
    let uint8 = new Uint8Array(length);
    for (let i = 0; i < length; i++) uint8[i] = parseInt(hexValue.substr(i * 2, 2), 16);

    return uint8;
}

export function h512(m: Uint8Array) {
    let shaObj = new jsSHA('SHA-512', 'UINT8ARRAY')
    shaObj.update(m)
    return shaObj.getHash('UINT8ARRAY');
}

export function h512_blake2b(m: Uint8Array) {
    return blake.blake2b(m)

}

export function h256(m: Uint8Array) {
    let shaObj = new jsSHA('SHA-256', 'UINT8ARRAY')
    shaObj.update(m)
    return shaObj.getHash('UINT8ARRAY')
}

export function Fk(message: Uint8Array, secret: Uint8Array) {
    let shaObj = new jsSHA('SHA-512', 'UINT8ARRAY')
    shaObj.setHMACKey(secret, 'UINT8ARRAY')
    shaObj.update(message)
    return shaObj.getHMAC('UINT8ARRAY')
}

export function set_bit(character: number, pattern: number) {
    return character | pattern
}

export function clear_bit(character: number, pattern: number) {
    return character & ~pattern
}

export function root_key(masterSecret: Uint8Array): Node {
    if (masterSecret.length !== 32)
        throw new Error('Master secret must be 32 bytes (a Uint8Array of size 32)')
    let k = h512(masterSecret)
    let kL = k.slice(0, 32)
    let kR = k.slice(32)

    if (kL[31] & 0b00100000) {
        throw new Error(`Invalid master secret`)
    }

    // clear lowest three bits of the first byte
    kL[0] = clear_bit(kL[0], 0b00000111)
    // clear highest bit of the last byte
    kL[31] = clear_bit(kL[31], 0b10000000)
    // set second highest bit of the last byte
    kL[31] = set_bit(kL[31], 0b01000000)

    // root public key
    let A = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(bytes2bi(kL))))
    // root chain code
    let c = h256(concatUint8Arrays([new Uint8Array([1]), masterSecret]))
    return [[kL, kR], A, c]
}

export function private_child_key(node: Node, i: number | string | BigInteger): Node {
    if (!(i instanceof BigInteger)) i = bi(i)
    let [[kLP, kRP], AP, cP] = node
    if (!(i.greaterOrEqualTo(zero) && i.lesserThan(two.pow(32)))) {
        throw new Error('Index i must be between 0 and 2^32 - 1, inclusive')
    }

    let iBytes = new Uint8Array(bi2bytes(i, 4))
    let Z: Uint8Array
    let c: Uint8Array
    if (i.lesserThan(two.pow(31))) {
        // regular child
        Z = Fk(concatUint8Arrays([new Uint8Array([2]), new Uint8Array(AP), iBytes]), cP)
        c = Fk(concatUint8Arrays([new Uint8Array([3]), new Uint8Array(AP), iBytes]), cP).slice(32)
    } else {
        // hardened child
        Z = Fk(concatUint8Arrays([new Uint8Array([0]), kLP, kRP, iBytes]), cP)
        c = Fk(concatUint8Arrays([new Uint8Array([1]), kLP, kRP, iBytes]), cP).slice(32)
    }

    let ZL = Z.slice(0, 28)
    let ZR = Z.slice(32)

    let kLn = bytes2bi(ZL).times(bi(8)).plus(bytes2bi(kLP))
    // 'If kL is divisible by the base order n, discard the child.'
    // - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if (kLn.mod(ed25519.l).equals(zero))
        return private_child_key(node, i.plus(one))
    let kRn = (
        bytes2bi(ZR).plus(bytes2bi(kRP))
    ).mod(two.pow(256))
    let kL = new Uint8Array(bi2bytes(kLn, 32))
    let kR = new Uint8Array(bi2bytes(kRn, 32))

    let A = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(bytes2bi(kL))))
    return [[kL, kR], A, c]
}

export function safe_public_child_key(publicNode: PublicNode, i: number | string | BigInteger): PublicNode {
    if (!(i instanceof BigInteger)) i = bi(i)
    let [AP, cP] = publicNode
    if (!AP) {
        throw new Error(`public key required`)
    }
    if (!cP) {
        throw new Error(`chain code required`)
    }
    if (!(i.greaterOrEqualTo(zero) && i.lesserThan(two.pow(32)))) {
        throw new Error('Index i must be between 0 and 2^32 - 1, inclusive')
    }

    let iBytes = bi2bytes(i, 4)
    if (!i.lesserThan(two.pow(31))) { // If not regular, non-hardened child
        throw new Error(`Can't create hardened child keys from public key`)
    }
    let Z = Fk(concatUint8Arrays([new Uint8Array([2]), AP, iBytes]), cP)
    let c = Fk(concatUint8Arrays([new Uint8Array([3]), new Uint8Array(AP), iBytes]), cP).slice(32)

    let ZL = Z.slice(0, 28)
    let ZR = Z.slice(32)

    let A = ed25519.encodepoint(
        ed25519.edwards(ed25519.decodepoint(AP), ed25519.scalarmultbase((bytes2bi(ZL).times(bi(8)))))
    )

    // VERY IMPORTANT. DO NOT USE A CHILD KEY THAT IS EQUIVALENT TO THE IDENTITY POINT
    // 'If Ai is the identity point (0, 1), discard the child.'
    // - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if (bytes2bi(A).equals(bytes2bi(ed25519.encodepoint([one, zero])))) {
        return safe_public_child_key(publicNode, i.plus(one))
    }

    return [A, c]
}

/** private/secret key left and right sides kL & kR, public key A, and message M in bytes */
export function special_signing(kL: Uint8Array, kR: Uint8Array, A: Uint8Array, M: Uint8Array) {
    let r = h512_blake2b(concatUint8Arrays([kR, M]))

    r = bytes2bi(r).mod(ed25519.l) // l is  base order n of Section III of 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace'
    let R = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(r)))
    let x = bytes2bi(h512_blake2b(concatUint8Arrays([R, A, M])))
    let S = new Uint8Array(ed25519.encodeint(r.plus(x.times(bytes2bi(kL))).mod(ed25519.l)))
    return concatUint8Arrays([R, S])
}

// 'Let k_tilde be 256-bit master secret. Then derive k = H512(k_tilde)
// and denote its left 32-byte by kL and right one by kR. If the
// third highest bit of the last byte of kL is not zero, discard k_tilde'
// - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
// Instead of discarding, incrementally try hashing 32 bit integers starting at 0 with the seed until
// a valid master secret is found.
export function seed_to_master_secret(seed: Uint8Array) {
    let i = 0
    while (true) {
        let k = h512(!i ? seed : concatUint8Arrays([bi2bytes(i, 4), seed]))

        if (!(k[31] & 0b00100000)) {
            return seed
        }
        i++
    }
}

export function generate_master_secret() {
    let seed = new Uint8Array(32)
    crypto.randomFillSync(seed)
    return seed_to_master_secret(seed)
}


export function derive_path(masterSecret: Uint8Array, path: string): Node {
    let root = root_key(masterSecret)
    let node: Node = root

    for (let i = 0, chain = path.split('/'); i < chain.length; i++) {
        if (!chain[i])
            continue
        const index = chain[i].endsWith(`'`)
            ? bi(chain[i].slice(0, -1)).plus(two.pow(31))
            : bi(chain[i])
        node = private_child_key(node, chain[i])
    }
    return node
}
