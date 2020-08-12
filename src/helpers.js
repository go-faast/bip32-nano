"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsbn_1 = require("jsbn");
exports.BigInteger = jsbn_1.BigInteger;
function chr(n) {
    return String.fromCharCode(n);
}
function ord(c) {
    return c.charCodeAt(0);
}
function map(f, l) {
    const result = new Array(l.length);
    for (let i = 0; i < l.length; i++)
        result[i] = f(l[i]);
    return result;
}
function bytes2string(bytes) {
    return map(chr, bytes).join('');
}
exports.bytes2string = bytes2string;
function string2bytes(s) {
    return new Uint8Array(map(ord, s));
}
exports.string2bytes = string2bytes;
function bi2bytes(n, cnt) {
    if (typeof cnt === 'undefined')
        cnt = (n.bitLength() >> 3) + 1;
    const bytes = new Uint8Array(cnt);
    for (let i = 0; i < cnt; i++) {
        bytes[i] = n[0] & 255; // n.and(xff);
        n = n.shiftRight(8);
    }
    return bytes;
}
exports.bi2bytes = bi2bytes;
function bytes2bi(bytes) {
    let n = bi('0');
    for (let i = bytes.length - 1; i > -1; i--) {
        n = n.shiftLeft(8).or(bi('' + bytes[i]));
    }
    return n;
}
exports.bytes2bi = bytes2bi;
function hex2bi(s) {
    return new jsbn_1.BigInteger(s, 16);
}
exports.hex2bi = hex2bi;
function concatUint8Arrays(uint8Arrays) {
    let concatenatedArrayLength = 0;
    uint8Arrays.forEach(arr => {
        concatenatedArrayLength += arr.length;
    });
    let concatenatedArray = new Uint8Array(concatenatedArrayLength);
    for (let i = 0, startingLengthOfSetOp = 0; i < uint8Arrays.length; i++) {
        if (i === 0) {
            concatenatedArray.set(uint8Arrays[0]);
        }
        else {
            startingLengthOfSetOp += uint8Arrays[i - 1].length;
            concatenatedArray.set(uint8Arrays[i], startingLengthOfSetOp);
        }
    }
    return concatenatedArray;
}
exports.concatUint8Arrays = concatUint8Arrays;
jsbn_1.BigInteger.prototype.times = jsbn_1.BigInteger.prototype.multiply;
jsbn_1.BigInteger.prototype.plus = jsbn_1.BigInteger.prototype.add;
jsbn_1.BigInteger.prototype.minus = jsbn_1.BigInteger.prototype.subtract;
jsbn_1.BigInteger.prototype.square = function () {
    return this.times(this);
};
jsbn_1.BigInteger.prototype.lesser = function (a) {
    return (this.compareTo(a) < 0);
};
jsbn_1.BigInteger.prototype.greater = function (a) {
    return (this.compareTo(a) > 0);
};
jsbn_1.BigInteger.prototype.greaterOrEqualTo = function (a) {
    return (this.compareTo(a) >= 0);
};
jsbn_1.BigInteger.prototype.lesserOrEqualTo = function (a) {
    return (this.compareTo(a) >= 0);
};
jsbn_1.BigInteger.prototype.lesserThan = jsbn_1.BigInteger.prototype.lesser;
jsbn_1.BigInteger.prototype.greaterThan = jsbn_1.BigInteger.prototype.greater;
jsbn_1.BigInteger.prototype.equalTo = jsbn_1.BigInteger.prototype.equals;
// BigInteger construction done right
function bi(s, base) {
    if (typeof base !== 'undefined') {
        if (base === 256)
            return bytes2bi(string2bytes(s));
        return new jsbn_1.BigInteger(s, base);
    }
    else if (typeof s === 'string') {
        return new jsbn_1.BigInteger(s, 10);
    }
    else if (s instanceof Uint8Array) {
        return bytes2bi(s);
    }
    else if (typeof s === 'number') {
        return new jsbn_1.BigInteger(s.toString(), 10);
    }
    else {
        throw new Error(`Can't convert ${s} to BigInteger`);
    }
}
exports.bi = bi;
exports.zero = jsbn_1.BigInteger.ZERO;
exports.one = jsbn_1.BigInteger.ONE;
exports.two = bi('2');
