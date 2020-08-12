"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("./crypto");
const bs58check = require('bs58check');
const typeforce = require('typeforce');
const bip32ed25519 = require("./bip32_ed25519");
const ed25519 = require("./ed25519");
const helpers_1 = require("./helpers");
const UINT512_TYPE = typeforce.BufferN(64);
const UINT256_TYPE = typeforce.BufferN(32);
const NETWORK_TYPE = typeforce.compile({
    wif: typeforce.UInt8,
    bip32: {
        public: typeforce.UInt32,
        private: typeforce.UInt32,
    },
});
const NANO = {
    messagePrefix: '',
    bech32: '',
    bip32: {
        public: 0x0488b21e,
        private: 0x0488ade4,
    },
    pubKeyHash: 0,
    scriptHash: 0,
    wif: 0,
};
const HIGHEST_BIT = 0x80000000;
const UINT31_MAX = Math.pow(2, 31) - 1;
const BASE58_PUBLIC_BYTE_COUNT = 4 + 1 + 4 + 4 + 32 + 32;
const BASE58_PRIVATE_BYTE_COUNT = 4 + 1 + 4 + 4 + 32 + 64;
function BIP32Path(value) {
    return (typeforce.String(value) && value.match(/^(m\/)?(\d+'?\/)*\d+'?$/) !== null);
}
function UInt31(value) {
    return typeforce.UInt32(value) && value <= UINT31_MAX;
}
class BIP32Nano {
    constructor(__KL, __KR, __A, chainCode, network, __DEPTH = 0, __INDEX = 0, __PARENT_FINGERPRINT = 0x00000000) {
        this.__KL = __KL;
        this.__KR = __KR;
        this.__A = __A;
        this.chainCode = chainCode;
        this.network = network;
        this.__DEPTH = __DEPTH;
        this.__INDEX = __INDEX;
        this.__PARENT_FINGERPRINT = __PARENT_FINGERPRINT;
        typeforce(NETWORK_TYPE, network);
        this.lowR = false;
    }
    get depth() {
        return this.__DEPTH;
    }
    get index() {
        return this.__INDEX;
    }
    get parentFingerprint() {
        return this.__PARENT_FINGERPRINT;
    }
    get publicKey() {
        if (typeof this.__A === 'undefined') {
            this.__A = Buffer.from(ed25519.encodepoint(ed25519.scalarmultbase(helpers_1.bytes2bi(this.__KL))));
        }
        return this.__A;
    }
    get privateKey() {
        if (this.isNeutered()) {
            return;
        }
        return Buffer.concat([this.__KL, this.__KR]);
    }
    get identifier() {
        return crypto.hash160(this.publicKey);
    }
    get fingerprint() {
        return this.identifier.slice(0, 4);
    }
    // Private === not neutered
    // Public === neutered
    isNeutered() {
        return typeof this.__KL === 'undefined' || typeof this.__KR === 'undefined';
    }
    neutered() {
        return fromPublicKeyLocal(this.publicKey, this.chainCode, this.network, this.depth, this.index, this.parentFingerprint);
    }
    toBase58() {
        const network = this.network;
        const version = !this.isNeutered()
            ? network.bip32.private
            : network.bip32.public;
        const buffer = !this.isNeutered()
            ? Buffer.allocUnsafe(BASE58_PRIVATE_BYTE_COUNT)
            : Buffer.allocUnsafe(BASE58_PUBLIC_BYTE_COUNT);
        // 4 bytes: version bytes
        buffer.writeUInt32BE(version, 0);
        // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ....
        buffer.writeUInt8(this.depth, 4);
        // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
        buffer.writeUInt32BE(this.parentFingerprint, 5);
        // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
        // This is encoded in big endian. (0x00000000 if master key)
        buffer.writeUInt32BE(this.index, 9);
        // 32 bytes: the chain code
        this.chainCode.copy(buffer, 13);
        // 64 bytes: the public key (32 bytes) or extended private key data (64 bytes)
        if (!this.isNeutered()) {
            this.privateKey.copy(buffer, 45);
        }
        else {
            // 32 bytes: the public key
            this.publicKey.copy(buffer, 45);
        }
        return bs58check.encode(buffer);
    }
    toWIF() {
        throw new Error('toWIF not supported for bip32 ed25519');
    }
    derive(index) {
        typeforce(typeforce.UInt32, index);
        const isHardened = index >= HIGHEST_BIT;
        // Hardened child
        if (isHardened && this.isNeutered()) {
            throw new TypeError('Missing private key for hardened child key');
        }
        // Private parent key -> private child key
        let hd;
        if (!this.isNeutered()) {
            const [[kL, kR], publicKey, chainCode] = bip32ed25519.private_child_key([[this.__KL, this.__KR], this.publicKey, this.chainCode], index);
            hd = new BIP32Nano(Buffer.from(kL), Buffer.from(kR), Buffer.from(publicKey), Buffer.from(chainCode), this.network, this.depth + 1, index, this.fingerprint.readUInt32BE(0));
        }
        else {
            // Public parent key -> public child key
            const [publicKey, chainCode] = bip32ed25519.safe_public_child_key([this.publicKey, this.chainCode], index);
            hd = new BIP32Nano(undefined, undefined, Buffer.from(publicKey), Buffer.from(chainCode), this.network, this.depth + 1, index, this.fingerprint.readUInt32BE(0));
        }
        return hd;
    }
    deriveHardened(index) {
        typeforce(UInt31, index);
        // Only derives hardened private keys by default
        return this.derive(index + HIGHEST_BIT);
    }
    derivePath(path) {
        typeforce(BIP32Path, path);
        let splitPath = path.split('/');
        if (splitPath[0] === 'm') {
            if (this.parentFingerprint)
                throw new TypeError('Expected master, got child');
            splitPath = splitPath.slice(1);
        }
        return splitPath.reduce((prevHd, indexStr) => {
            let index;
            if (indexStr.slice(-1) === `'`) {
                index = parseInt(indexStr.slice(0, -1), 10);
                return prevHd.deriveHardened(index);
            }
            else {
                index = parseInt(indexStr, 10);
                return prevHd.derive(index);
            }
        }, this);
    }
    sign(hash) {
        if (!this.privateKey)
            throw new Error('Missing private key');
        return Buffer.from(bip32ed25519.special_signing(this.__KL, this.__KR, this.publicKey, hash));
    }
    verify(hash, signature) {
        return ed25519.checksig(signature, hash, this.publicKey);
    }
}
function fromBase58(inString, network) {
    const buffer = bs58check.decode(inString);
    if (buffer.length !== BASE58_PRIVATE_BYTE_COUNT || buffer.length !== BASE58_PUBLIC_BYTE_COUNT) {
        throw new TypeError('Invalid buffer length');
    }
    network = network || NANO;
    // 4 bytes: version bytes
    const version = buffer.readUInt32BE(0);
    if (version !== network.bip32.private && version !== network.bip32.public)
        throw new TypeError('Invalid network version');
    // 1 byte: depth: 0x00 for master nodes, 0x01 for level-1 descendants, ...
    const depth = buffer[4];
    // 4 bytes: the fingerprint of the parent's key (0x00000000 if master key)
    const parentFingerprint = buffer.readUInt32BE(5);
    if (depth === 0) {
        if (parentFingerprint !== 0x00000000)
            throw new TypeError('Invalid parent fingerprint');
    }
    // 4 bytes: child number. This is the number i in xi = xpar/i, with xi the key being serialized.
    // This is encoded in MSB order. (0x00000000 if master key)
    const index = buffer.readUInt32BE(9);
    if (depth === 0 && index !== 0)
        throw new TypeError('Invalid index');
    // 32 bytes: the chain code
    const chainCode = buffer.slice(13, 45);
    let hd;
    // 33 bytes: private key data (0x00 + k)
    if (version === network.bip32.private) {
        if (buffer.length !== BASE58_PRIVATE_BYTE_COUNT)
            throw new TypeError('Invalid private key length');
        const K = buffer.slice(45, 109);
        hd = fromPrivateKeyLocal(K, chainCode, network, depth, index, parentFingerprint);
        // 33 bytes: public key data (0x02 + X or 0x03 + X)
    }
    else {
        if (buffer.length !== BASE58_PUBLIC_BYTE_COUNT)
            throw new TypeError('Invalid public key length');
        const X = buffer.slice(45, 78);
        hd = fromPublicKeyLocal(X, chainCode, network, depth, index, parentFingerprint);
    }
    return hd;
}
exports.fromBase58 = fromBase58;
function fromPrivateKey(privateKey, chainCode, network) {
    return fromPrivateKeyLocal(privateKey, chainCode, network);
}
exports.fromPrivateKey = fromPrivateKey;
function fromPrivateKeyLocal(privateKey, chainCode, network, depth, index, parentFingerprint) {
    typeforce({
        privateKey: UINT512_TYPE,
        chainCode: UINT256_TYPE,
    }, { privateKey, chainCode });
    network = network || NANO;
    return new BIP32Nano(privateKey.slice(0, 32), privateKey.slice(32), undefined, chainCode, network, depth, index, parentFingerprint);
}
function fromPublicKey(publicKey, chainCode, network) {
    return fromPublicKeyLocal(publicKey, chainCode, network);
}
exports.fromPublicKey = fromPublicKey;
function fromPublicKeyLocal(publicKey, chainCode, network, depth, index, parentFingerprint) {
    typeforce({
        publicKey: UINT256_TYPE,
        chainCode: UINT256_TYPE,
    }, { publicKey, chainCode });
    network = network || NANO;
    // verify the X coordinate is a point on the curve
    ed25519.decodepoint(publicKey);
    return new BIP32Nano(undefined, undefined, publicKey, chainCode, network, depth, index, parentFingerprint);
}
function fromSeed(seed, network) {
    typeforce(typeforce.Buffer, seed);
    if (seed.length < 16)
        throw new TypeError('Seed should be at least 128 bits');
    if (seed.length > 64)
        throw new TypeError('Seed should be at most 512 bits');
    network = network || NANO;
    const masterSecret = bip32ed25519.seed_to_master_secret(seed);
    const [[KL, KR], publicKey, chainCode] = bip32ed25519.root_key(masterSecret);
    return new BIP32Nano(Buffer.from(KL), Buffer.from(KR), Buffer.from(publicKey), Buffer.from(chainCode), network);
}
exports.fromSeed = fromSeed;
