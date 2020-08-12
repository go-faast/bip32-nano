import { BigInteger } from './helpers';
export declare function inthash(s: any): BigInteger;
declare type Point = [BigInteger, BigInteger];
export declare let l: BigInteger;
declare let bp: Point;
export declare function edwards(p1: Point, p2: Point): Point;
export declare function scalarmult(pt: Point, n: BigInteger): Point;
export declare function scalarmultbase(e: BigInteger): Point;
export declare function encodeint(n: BigInteger): Uint8Array;
export declare function decodeint(a: Uint8Array): BigInteger;
export declare function encodepoint(p: Point): Uint8Array;
export declare function publickey(sk: string | Uint8Array): Uint8Array;
export declare function signature(m: string | Uint8Array, sk: string | Uint8Array, pk: Uint8Array): Uint8Array;
export declare function isoncurve(p: Point): boolean;
export declare function decodepoint(v: Uint8Array): [BigInteger, BigInteger];
export declare function checksig(sig: Uint8Array, msg: string | Uint8Array, pk: Uint8Array): boolean;
export declare function sig_test(msg: string | Uint8Array): boolean;
export declare function curve25519(n: BigInteger, base?: BigInteger): BigInteger;
export declare function dh_test(sk1: BigInteger, sk2: BigInteger): boolean;
export { curve25519 as ecDH, bp as B };