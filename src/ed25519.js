"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const blake = require('blakejs');
const helpers_1 = require("./helpers");
//  Ed25519 - digital signatures based on curve25519
//  Adapted from http://ed25519.cr.yp.to/python/ed25519.py by Ron Garret
function hash(m) {
    return blake.blake2b(m);
}
function inthash(s) {
    return helpers_1.bytes2bi(hash(s));
}
exports.inthash = inthash;
function stringhash(s) {
    return helpers_1.bytes2string(hash(s));
}
let xff = 255;
let q = helpers_1.two.pow(255).minus(helpers_1.bi('19'));
exports.l = helpers_1.two.pow(252).add(helpers_1.bi('27742317777372353535851937790883648493'));
let k1 = helpers_1.two.pow(254);
let k2 = helpers_1.two.pow(251).minus(helpers_1.one).shiftLeft(3);
function inv(n) {
    return n.mod(q).modInverse(q);
}
let d = helpers_1.bi('-121665').times(inv(helpers_1.bi('121666'))).mod(q);
let i = helpers_1.two.modPow(q.minus(helpers_1.one).divide(helpers_1.bi('4')), q);
function xrecover(y) {
    let ysquared = y.times(y);
    let xx = ysquared.minus(helpers_1.one).times(inv(helpers_1.one.add(d.times(ysquared))));
    let x = xx.modPow(q.add(helpers_1.bi('3')).divide(helpers_1.bi('8')), q);
    if (!(x.times(x).minus(xx).mod(q).equals(helpers_1.zero))) {
        x = x.times(i).mod(q);
    }
    if (!(x.mod(helpers_1.two).equals(helpers_1.zero))) {
        x = q.minus(x);
    }
    return x;
}
let by = inv(helpers_1.bi('5')).times(helpers_1.bi('4')).mod(q);
let bx = xrecover(by);
let bp = [bx, by];
exports.B = bp;
// Simple but slow version
function edwards(p1, p2) {
    let x1 = p1[0];
    let y1 = p1[1];
    let x2 = p2[0];
    let y2 = p2[1];
    let k = d.times(x1).times(x2).times(y1).times(y2);
    let x3 = x1.times(y2).add(x2.times(y1)).times(inv(helpers_1.one.plus(k)));
    let y3 = y1.times(y2).add(x1.times(x2)).times(inv(helpers_1.one.minus(k)));
    return [x3.mod(q), y3.mod(q)];
}
exports.edwards = edwards;
function slow_scalarmult(p, e) {
    if (e.equals(helpers_1.zero))
        return [helpers_1.zero, helpers_1.one];
    let _ = scalarmult(p, e.divide(helpers_1.two));
    _ = edwards(_, _);
    if (e.testBit(0))
        return edwards(_, p);
    else
        return _;
}
// Faster (!) version based on:
// http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html
function xpt_add(pt1, pt2) {
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
    let C = z1.times(helpers_1.two).times(t2).mod(q);
    let D = t1.times(helpers_1.two).times(z2).mod(q);
    let E = D.plus(C);
    let F = B.minus(A);
    let G = B.plus(A);
    let H = D.minus(C);
    return [E.times(F).mod(q), G.times(H).mod(q),
        F.times(G).mod(q), E.times(H).mod(q)];
}
function xpt_double(pt1) {
    let x1 = pt1[0];
    let y1 = pt1[1];
    let z1 = pt1[2];
    let A = x1.times(x1);
    let B = y1.times(y1);
    let C = helpers_1.two.times(z1).times(z1);
    let D = helpers_1.zero.minus(A).mod(q);
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
function xpt_mult(pt, n) {
    if (n.equals(helpers_1.zero)) {
        return [helpers_1.zero, helpers_1.one, helpers_1.one, helpers_1.zero];
    }
    let _ = xpt_mult(pt, n.shiftRight(1));
    _ = xpt_double(_);
    if (n.and(helpers_1.one).compareTo(helpers_1.zero)) {
        return xpt_add(_, pt);
    } // if (n.testBit(0)) return xpt_add(_, pt);
    else {
        return _;
    }
}
function pt_xform(pt) {
    let x = pt[0];
    let y = pt[1];
    return [x, y, helpers_1.one, x.times(y).mod(q)];
}
function pt_unxform(pt) {
    let x = pt[0];
    let y = pt[1];
    let z = pt[2];
    let invz = inv(z);
    return [x.times(invz).mod(q), y.times(invz).mod(q)];
}
function scalarmult(pt, n) {
    return pt_unxform(xpt_mult(pt_xform(pt), n));
}
exports.scalarmult = scalarmult;
function scalarmultbase(e) {
    if (e === helpers_1.zero)
        return [helpers_1.zero, helpers_1.one];
    return scalarmult(bp, e);
}
exports.scalarmultbase = scalarmultbase;
function encodeint(n) {
    return helpers_1.bi2bytes(n, 32);
}
exports.encodeint = encodeint;
function decodeint(a) {
    return helpers_1.bytes2bi(a);
}
exports.decodeint = decodeint;
function encodepoint(p) {
    let x = p[0];
    let y = p[1];
    return encodeint(y.add(x.and(helpers_1.one).shiftLeft(255)));
}
exports.encodepoint = encodepoint;
function publickey(sk) {
    let h = inthash(sk);
    let a = k1.add(k2.and(h));
    return encodepoint(scalarmult(bp, a));
}
exports.publickey = publickey;
function signature(m, sk, pk) {
    if (typeof m === 'string') {
        m = new Uint8Array(helpers_1.string2bytes(m));
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
    let s = r.add(a.times(s0)).mod(exports.l);
    return helpers_1.concatUint8Arrays([encodepoint(rp), encodeint(s)]);
}
exports.signature = signature;
function isoncurve(p) {
    let x = p[0];
    let y = p[1];
    let v = d.times(x).times(x).times(y).times(y).mod(q);
    return y.times(y).minus(x.times(x)).minus(helpers_1.one).minus(v).mod(q).equals(helpers_1.zero);
}
exports.isoncurve = isoncurve;
function decodepoint(v) {
    let y = helpers_1.bytes2bi(v).and(helpers_1.two.pow(xff).minus(helpers_1.one));
    let x = xrecover(y);
    if ((x.testBit(0) ? 1 : 0) !== v[31] >> 7)
        x = q.minus(x);
    let p = [x, y];
    if (!isoncurve(p))
        throw new Error('Point is not on curve');
    return p;
}
exports.decodepoint = decodepoint;
function checksig(sig, msg, pk) {
    if (typeof msg === 'string') {
        msg = new Uint8Array(helpers_1.string2bytes(msg));
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
exports.checksig = checksig;
function sig_test(msg) {
    let pk = publickey('foo');
    let sig = signature(msg, 'foo', pk);
    return checksig(sig, msg, pk);
}
exports.sig_test = sig_test;
///////////////////////////////////////////////////////
//
//  Curve25519 diffie-helman
//
function zpt_add(xz1, xz2, base) {
    let x1 = xz1[0];
    let x2 = xz2[0];
    let z1 = xz1[1];
    let z2 = xz2[1];
    let x = x2.times(x1).minus(z2.times(z1)).square().shiftLeft(2).mod(q);
    let z = x2.times(z1).minus(z2.times(x1)).square().shiftLeft(2).times(base).mod(q);
    return [x, z];
}
function zpt_double(xz) {
    let x = xz[0];
    let z = xz[1];
    let x1 = x.square().minus(z.square()).square().mod(q);
    let z1 = x.times(z).times(x.square().plus(helpers_1.bi('486662').times(x).times(z).plus(z.square()))).shiftLeft(2).mod(q);
    return [x1, z1];
}
function zpt_sm(n, base) {
    let bp1 = [base, helpers_1.one];
    let bp2 = zpt_double(bp);
    function f(m) {
        if (m.equals(helpers_1.one))
            return [bp1, bp2];
        let pmpm1 = f(m.shiftRight(1));
        let pm = pmpm1[0];
        let pm1 = pmpm1[1];
        if (m.testBit(0))
            return [zpt_add(pm, pm1, base), zpt_double(pm1)];
        else
            return [zpt_double(pm), zpt_add(pm, pm1, base)];
    }
    return f(n);
}
function curve25519(n, base = helpers_1.bi(9)) {
    let xz = zpt_sm(n, base);
    let x = xz[0][0];
    let z = xz[0][1];
    return x.times(z.modInverse(q)).mod(q);
}
exports.curve25519 = curve25519;
exports.ecDH = curve25519;
function dh_test(sk1, sk2) {
    let pk1 = curve25519(sk1);
    let pk2 = curve25519(sk2);
    return curve25519(sk1, pk2).equals(curve25519(sk2, pk1));
}
exports.dh_test = dh_test;
