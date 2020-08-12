const blake = require('blakejs')
import { BigInteger, bi, zero, one, two, bytes2bi, bytes2string, bi2bytes, string2bytes, concatUint8Arrays } from './helpers'

//  Ed25519 - digital signatures based on curve25519
//  Adapted from http://ed25519.cr.yp.to/python/ed25519.py by Ron Garret

function hash(m: string | Buffer | Uint8Array) {
    return blake.blake2b(m)
}

export function inthash(s: any) {
    return bytes2bi(hash(s));
}

function stringhash(s: string) {
    return bytes2string(hash(s));
}

type Point = [BigInteger, BigInteger]
type XPoint = [BigInteger, BigInteger, BigInteger, BigInteger]

let xff = 255;
let q = two.pow(255).minus(bi('19'));
export let l = two.pow(252).add(bi('27742317777372353535851937790883648493'));

let k1 = two.pow(254);
let k2 = two.pow(251).minus(one).shiftLeft(3);

function inv(n: BigInteger) {
    return n.mod(q).modInverse(q);
}

let d = bi('-121665').times(inv(bi('121666'))).mod(q);
let i = two.modPow(q.minus(one).divide(bi('4')), q);

function xrecover(y: BigInteger) {
    let ysquared = y.times(y);
    let xx = ysquared.minus(one).times(inv(one.add(d.times(ysquared))));
    let x = xx.modPow(q.add(bi('3')).divide(bi('8')), q);
    if (!(x.times(x).minus(xx).mod(q).equals(zero))) {
        x = x.times(i).mod(q);
    }
    if (!(x.mod(two).equals(zero))) {
        x = q.minus(x);
    }
    return x;
}

let by = inv(bi('5')).times(bi('4')).mod(q);
let bx = xrecover(by);
let bp: Point = [bx, by]

// Simple but slow version

export function edwards(p1: Point, p2: Point): Point {
    let x1 = p1[0];
    let y1 = p1[1];
    let x2 = p2[0];
    let y2 = p2[1];
    let k = d.times(x1).times(x2).times(y1).times(y2);
    let x3 = x1.times(y2).add(x2.times(y1)).times(inv(one.plus(k)));
    let y3 = y1.times(y2).add(x1.times(x2)).times(inv(one.minus(k)));
    return [x3.mod(q), y3.mod(q)];
}

function slow_scalarmult(p: Point, e: BigInteger): Point {
    if (e.equals(zero)) return [zero, one];
    let _: any = scalarmult(p, e.divide(two));
    _ = edwards(_, _)
    if (e.testBit(0)) return edwards(_, p);
    else return _;
}

// Faster (!) version based on:
// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html

function xpt_add(pt1: XPoint, pt2: XPoint): XPoint {
    let x1 = pt1[0];
    let y1 = pt1[1];
    let z1 = pt1[2];
    let t1 = pt1[3];
    let x2 = pt2[0];
    let y2 = pt2[1];
    let z2 = pt2[2];
    let t2 = pt2[3];
    let A = y1.minus(x1).times(y2.plus(x2)).mod(q);
    let B = y1.plus(x1).times(y2.minus(x2)).mod(q);
    let C = z1.times(two).times(t2).mod(q);
    let D = t1.times(two).times(z2).mod(q);
    let E = D.plus(C);
    let F = B.minus(A);
    let G = B.plus(A);
    let H = D.minus(C);
    return [E.times(F).mod(q), G.times(H).mod(q),
        F.times(G).mod(q), E.times(H).mod(q)];
}

function xpt_double(pt1: XPoint) {
    let x1 = pt1[0];
    let y1 = pt1[1];
    let z1 = pt1[2];
    let A = x1.times(x1);
    let B = y1.times(y1);
    let C = two.times(z1).times(z1);
    let D = zero.minus(A).mod(q);
    let J = x1.plus(y1).mod(q);
    let E = J.times(J).minus(A).minus(B).mod(q);
    let G = D.plus(B).mod(q);
    let F = G.minus(C).mod(q);
    let H = D.minus(B).mod(q);
    let X3 = E.times(F).mod(q);
    let Y3 = G.times(H).mod(q);
    let Z3 = F.times(G).mod(q);
    let T3 = E.times(H).mod(q);
    return [X3, Y3, Z3, T3];
}

function xpt_mult(pt: XPoint, n: BigInteger): XPoint {
    if (n.equals(zero)) {
        return [zero, one, one, zero];
    }
    let _: any = xpt_mult(pt, n.shiftRight(1));
    _ = xpt_double(_);
    if (n.and(one).compareTo(zero)) {
        return xpt_add(_, pt);
    } // if (n.testBit(0)) return xpt_add(_, pt);
    else {
        return _;
    }
}

function pt_xform(pt: Point): XPoint {
    let x = pt[0];
    let y = pt[1];
    return [x, y, one, x.times(y).mod(q)]
}

function pt_unxform(pt: XPoint): Point {
    let x = pt[0];
    let y = pt[1];
    let z = pt[2];
    let invz = inv(z);
    return [x.times(invz).mod(q), y.times(invz).mod(q)]
}

export function scalarmult(pt: Point, n: BigInteger): Point {
    return pt_unxform(xpt_mult(pt_xform(pt), n));
}

export function scalarmultbase(e: BigInteger): Point {
    if (e === zero) return [zero, one]
    return scalarmult(bp, e)
}

export function encodeint(n: BigInteger): Uint8Array {
    return bi2bytes(n, 32);
}

export function decodeint(a: Uint8Array): BigInteger {
    return bytes2bi(a);
}

export function encodepoint(p: Point): Uint8Array {
    let x = p[0];
    let y = p[1];
    return encodeint(y.add(x.and(one).shiftLeft(255)));
}

export function publickey(sk: string | Uint8Array): Uint8Array {
    let h = inthash(sk);
    let a = k1.add(k2.and(h));
    return encodepoint(scalarmult(bp, a));
}

export function signature(m: string | Uint8Array, sk: string | Uint8Array, pk: Uint8Array) {
    if (typeof m === 'string') {
        m = new Uint8Array(string2bytes(m));
    }
    let hi = inthash(sk);
    let hs = hash(sk);
    let a = k1.add(k2.and(hi));
    let rdata = new Uint8Array(32 + m.length);
    rdata.set(hs.slice(32, 64));
    rdata.set(m, 32);
    let r = inthash(rdata);
    let rp = scalarmult(bp, r);
    let s0data = new Uint8Array(32 + pk.length + m.length);
    s0data.set(encodepoint(rp));
    s0data.set(pk, 32);
    s0data.set(m, 32 + pk.length);
    let s0 = inthash(s0data);
    let s = r.add(a.times(s0)).mod(l);
    return concatUint8Arrays([encodepoint(rp), encodeint(s)]);
}

export function isoncurve(p: Point) {
    let x = p[0];
    let y = p[1];
    let v = d.times(x).times(x).times(y).times(y).mod(q);
    return y.times(y).minus(x.times(x)).minus(one).minus(v).mod(q).equals(zero);
}

export function decodepoint(v: Uint8Array) {
    let y = bytes2bi(v).and(two.pow(xff).minus(one));
    let x = xrecover(y);
    if ((x.testBit(0) ? 1 : 0) !== v[31] >> 7) x = q.minus(x);
    let p: Point = [x, y];
    if (!isoncurve(p)) throw new Error('Point is not on curve');
    return p;
}

export function checksig(sig: Uint8Array, msg: string | Uint8Array, pk: Uint8Array) {
    if (typeof msg === 'string') {
        msg = new Uint8Array(string2bytes(msg));
    }
    let r = decodepoint(sig.slice(0, 32));
    let a = decodepoint(pk);
    let s = decodeint(sig.slice(32, 64));
    let hdata = new Uint8Array(32 + pk.length + msg.length);
    hdata.set(encodepoint(r));
    hdata.set(pk, 32);
    hdata.set(msg, 32 + pk.length);
    let h = inthash(hdata);
    let v1 = scalarmult(bp, s);
    let v2 = edwards(r, scalarmult(a, h));
    return v1[0].equals(v2[0]) && v1[1].equals(v2[1]);
}

export function sig_test(msg: string | Uint8Array) {
    let pk = publickey('foo');
    let sig = signature(msg, 'foo', pk);
    return checksig(sig, msg, pk);
}

///////////////////////////////////////////////////////
//
//  Curve25519 diffie-helman
//

function zpt_add(xz1: Point, xz2: Point, base: BigInteger): Point {
    let x1 = xz1[0];
    let x2 = xz2[0];
    let z1 = xz1[1];
    let z2 = xz2[1];
    let x = x2.times(x1).minus(z2.times(z1)).square().shiftLeft(2).mod(q);
    let z = x2.times(z1).minus(z2.times(x1)).square().shiftLeft(2).times(base).mod(q);
    return [x, z];
}

function zpt_double(xz: Point): Point {
    let x = xz[0];
    let z = xz[1];
    let x1 = x.square().minus(z.square()).square().mod(q);
    let z1 = x.times(z).times(x.square().plus(bi('486662').times(x).times(z).plus(z.square()))).shiftLeft(2).mod(q)
    return [x1, z1]
}

function zpt_sm(n: BigInteger, base: BigInteger): [Point, Point] {
    let bp1: Point = [base, one]
    let bp2 = zpt_double(bp);

    function f(m: BigInteger): [Point, Point] {
        if (m.equals(one)) return [bp1, bp2];
        let pmpm1 = f(m.shiftRight(1));
        let pm = pmpm1[0];
        let pm1 = pmpm1[1];
        if (m.testBit(0)) return [zpt_add(pm, pm1, base), zpt_double(pm1)];
        else return [zpt_double(pm), zpt_add(pm, pm1, base)];
    }

    return f(n);
}

export function curve25519(n: BigInteger, base: BigInteger = bi(9)): BigInteger {
    let xz = zpt_sm(n, base);
    let x = xz[0][0];
    let z = xz[0][1];
    return x.times(z.modInverse(q)).mod(q);
}

export function dh_test(sk1: BigInteger, sk2: BigInteger): boolean {
    let pk1 = curve25519(sk1);
    let pk2 = curve25519(sk2);
    return curve25519(sk1, pk2).equals(curve25519(sk2, pk1));
}

export { curve25519 as ecDH, bp as B }
