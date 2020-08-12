"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jssha_1 = require("jssha");
const crypto = require("crypto");
const blake = require('blakejs');
const ed25519 = require("./ed25519");
const helpers_js_1 = require("./helpers.js");
// Adapted from:
// https://github.com/superdarkbit/nano-bip32-ed25519/blob/master/src/js/bip32_ed25519.js
// With patches from the Nano team
function uint8ToHex(uintValue) {
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
exports.uint8ToHex = uint8ToHex;
function hexToUint8(hexValue) {
    let length = (hexValue.length / 2) | 0;
    let uint8 = new Uint8Array(length);
    for (let i = 0; i < length; i++)
        uint8[i] = parseInt(hexValue.substr(i * 2, 2), 16);
    return uint8;
}
exports.hexToUint8 = hexToUint8;
function h512(m) {
    let shaObj = new jssha_1.default('SHA-512', 'UINT8ARRAY');
    shaObj.update(m);
    return shaObj.getHash('UINT8ARRAY');
}
exports.h512 = h512;
function h512_blake2b(m) {
    return blake.blake2b(m);
}
exports.h512_blake2b = h512_blake2b;
function h256(m) {
    let shaObj = new jssha_1.default('SHA-256', 'UINT8ARRAY');
    shaObj.update(m);
    return shaObj.getHash('UINT8ARRAY');
}
exports.h256 = h256;
function Fk(message, secret) {
    let shaObj = new jssha_1.default('SHA-512', 'UINT8ARRAY');
    shaObj.setHMACKey(secret, 'UINT8ARRAY');
    shaObj.update(message);
    return shaObj.getHMAC('UINT8ARRAY');
}
exports.Fk = Fk;
function set_bit(character, pattern) {
    return character | pattern;
}
exports.set_bit = set_bit;
function clear_bit(character, pattern) {
    return character & ~pattern;
}
exports.clear_bit = clear_bit;
function root_key(masterSecret) {
    if (masterSecret.length !== 32)
        throw new Error('Master secret must be 32 bytes (a Uint8Array of size 32)');
    let k = h512(masterSecret);
    let kL = k.slice(0, 32);
    let kR = k.slice(32);
    if (kL[31] & 0b00100000) {
        throw new Error(`Invalid master secret`);
    }
    // clear lowest three bits of the first byte
    kL[0] = clear_bit(kL[0], 0b00000111);
    // clear highest bit of the last byte
    kL[31] = clear_bit(kL[31], 0b10000000);
    // set second highest bit of the last byte
    kL[31] = set_bit(kL[31], 0b01000000);
    // root public key
    let A = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(helpers_js_1.bytes2bi(kL))));
    // root chain code
    let c = h256(helpers_js_1.concatUint8Arrays([new Uint8Array([1]), masterSecret]));
    return [[kL, kR], A, c];
}
exports.root_key = root_key;
function private_child_key(node, i) {
    if (!(i instanceof helpers_js_1.BigInteger))
        i = helpers_js_1.bi(i);
    let [[kLP, kRP], AP, cP] = node;
    if (!(i.greaterOrEqualTo(helpers_js_1.zero) && i.lesserThan(helpers_js_1.two.pow(32)))) {
        throw new Error('Index i must be between 0 and 2^32 - 1, inclusive');
    }
    let iBytes = new Uint8Array(helpers_js_1.bi2bytes(i, 4));
    let Z;
    let c;
    if (i.lesserThan(helpers_js_1.two.pow(31))) {
        // regular child
        Z = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([2]), new Uint8Array(AP), iBytes]), cP);
        c = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([3]), new Uint8Array(AP), iBytes]), cP).slice(32);
    }
    else {
        // hardened child
        Z = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([0]), kLP, kRP, iBytes]), cP);
        c = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([1]), kLP, kRP, iBytes]), cP).slice(32);
    }
    let ZL = Z.slice(0, 28);
    let ZR = Z.slice(32);
    let kLn = helpers_js_1.bytes2bi(ZL).times(helpers_js_1.bi(8)).plus(helpers_js_1.bytes2bi(kLP));
    // 'If kL is divisible by the base order n, discard the child.'
    // - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if (kLn.mod(ed25519.l).equals(helpers_js_1.zero))
        return private_child_key(node, i.plus(helpers_js_1.one));
    let kRn = (helpers_js_1.bytes2bi(ZR).plus(helpers_js_1.bytes2bi(kRP))).mod(helpers_js_1.two.pow(256));
    let kL = new Uint8Array(helpers_js_1.bi2bytes(kLn, 32));
    let kR = new Uint8Array(helpers_js_1.bi2bytes(kRn, 32));
    let A = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(helpers_js_1.bytes2bi(kL))));
    return [[kL, kR], A, c];
}
exports.private_child_key = private_child_key;
function safe_public_child_key(publicNode, i) {
    if (!(i instanceof helpers_js_1.BigInteger))
        i = helpers_js_1.bi(i);
    let [AP, cP] = publicNode;
    if (!AP) {
        throw new Error(`public key required`);
    }
    if (!cP) {
        throw new Error(`chain code required`);
    }
    if (!(i.greaterOrEqualTo(helpers_js_1.zero) && i.lesserThan(helpers_js_1.two.pow(32)))) {
        throw new Error('Index i must be between 0 and 2^32 - 1, inclusive');
    }
    let iBytes = helpers_js_1.bi2bytes(i, 4);
    if (!i.lesserThan(helpers_js_1.two.pow(31))) { // If not regular, non-hardened child
        throw new Error(`Can't create hardened child keys from public key`);
    }
    let Z = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([2]), AP, iBytes]), cP);
    let c = Fk(helpers_js_1.concatUint8Arrays([new Uint8Array([3]), new Uint8Array(AP), iBytes]), cP).slice(32);
    let ZL = Z.slice(0, 28);
    let ZR = Z.slice(32);
    let A = ed25519.encodepoint(ed25519.edwards(ed25519.decodepoint(AP), ed25519.scalarmultbase((helpers_js_1.bytes2bi(ZL).times(helpers_js_1.bi(8))))));
    // VERY IMPORTANT. DO NOT USE A CHILD KEY THAT IS EQUIVALENT TO THE IDENTITY POINT
    // 'If Ai is the identity point (0, 1), discard the child.'
    // - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    if (helpers_js_1.bytes2bi(A).equals(helpers_js_1.bytes2bi(ed25519.encodepoint([helpers_js_1.one, helpers_js_1.zero])))) {
        return safe_public_child_key(publicNode, i.plus(helpers_js_1.one));
    }
    return [A, c];
}
exports.safe_public_child_key = safe_public_child_key;
/** private/secret key left and right sides kL & kR, public key A, and message M in bytes */
function special_signing(kL, kR, A, M) {
    let r = h512_blake2b(helpers_js_1.concatUint8Arrays([kR, M]));
    r = helpers_js_1.bytes2bi(r).mod(ed25519.l); // l is  base order n of Section III of 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace'
    let R = new Uint8Array(ed25519.encodepoint(ed25519.scalarmultbase(r)));
    let x = helpers_js_1.bytes2bi(h512_blake2b(helpers_js_1.concatUint8Arrays([R, A, M])));
    let S = new Uint8Array(ed25519.encodeint(r.plus(x.times(helpers_js_1.bytes2bi(kL))).mod(ed25519.l)));
    return helpers_js_1.concatUint8Arrays([R, S]);
}
exports.special_signing = special_signing;
// 'Let k_tilde be 256-bit master secret. Then derive k = H512(k_tilde)
// and denote its left 32-byte by kL and right one by kR. If the
// third highest bit of the last byte of kL is not zero, discard k_tilde'
// - 'BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace' (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
// Instead of discarding, incrementally try hashing 32 bit integers starting at 0 with the seed until
// a valid master secret is found.
function seed_to_master_secret(seed) {
    let i = 0;
    while (true) {
        let k = h512(!i ? seed : helpers_js_1.concatUint8Arrays([helpers_js_1.bi2bytes(i, 4), seed]));
        if (!(k[31] & 0b00100000)) {
            return seed;
        }
        i++;
    }
}
exports.seed_to_master_secret = seed_to_master_secret;
function generate_master_secret() {
    let seed = new Uint8Array(32);
    crypto.randomFillSync(seed);
    return seed_to_master_secret(seed);
}
exports.generate_master_secret = generate_master_secret;
function derive_path(masterSecret, path) {
    let root = root_key(masterSecret);
    let node = root;
    for (let i = 0, chain = path.split('/'); i < chain.length; i++) {
        if (!chain[i])
            continue;
        const index = chain[i].endsWith(`'`)
            ? helpers_js_1.bi(chain[i].slice(0, -1)).plus(helpers_js_1.two.pow(31))
            : helpers_js_1.bi(chain[i]);
        node = private_child_key(node, chain[i]);
    }
    return node;
}
exports.derive_path = derive_path;
