import { BigInteger } from './helpers.js';
declare type Node = [[Uint8Array, Uint8Array], Uint8Array, Uint8Array];
declare type PublicNode = [Uint8Array, Uint8Array];
export declare function uint8ToHex(uintValue: Uint8Array): string;
export declare function hexToUint8(hexValue: string): Uint8Array;
export declare function h512(m: Uint8Array): Uint8Array;
export declare function h512_blake2b(m: Uint8Array): any;
export declare function h256(m: Uint8Array): Uint8Array;
export declare function Fk(message: Uint8Array, secret: Uint8Array): Uint8Array;
export declare function set_bit(character: number, pattern: number): number;
export declare function clear_bit(character: number, pattern: number): number;
export declare function root_key(masterSecret: Uint8Array): Node;
export declare function private_child_key(node: Node, i: number | string | BigInteger): Node;
export declare function safe_public_child_key(publicNode: PublicNode, i: number | string | BigInteger): PublicNode;
/** private/secret key left and right sides kL & kR, public key A, and message M in bytes */
export declare function special_signing(kL: Uint8Array, kR: Uint8Array, A: Uint8Array, M: Uint8Array): Uint8Array;
export declare function seed_to_master_secret(seed: Uint8Array): Uint8Array;
export declare function generate_master_secret(): Uint8Array;
export declare function derive_path(masterSecret: Uint8Array, path: string): Node;
export {};
