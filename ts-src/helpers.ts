import { BigInteger } from 'jsbn';

function chr(n: number) {
    return String.fromCharCode(n);
}

function ord(c: string) {
    return c.charCodeAt(0);
}

function map<T, R>(f: (x: T) => R, l: any): R[] {
    const result = new Array(l.length);
    for (let i = 0; i < l.length; i++) result[i] = f(l[i]);
    return result;
}

export function bytes2string(bytes: Uint8Array): string {
    return map(chr, bytes).join('');
}

export function string2bytes(s: string): Uint8Array {
    return new Uint8Array(map(ord, s));
}

export function bi2bytes(n: any, cnt: number): Uint8Array {
    if (typeof cnt === 'undefined') cnt = (n.bitLength() >> 3) + 1;
    const bytes = new Uint8Array(cnt);
    for (let i = 0; i < cnt; i++) {
        bytes[i] = n[0] & 255;           // n.and(xff);
        n = n.shiftRight(8);
    }
    return bytes;
}

export function bytes2bi(bytes: Uint8Array): BigInteger {
    let n = bi('0');
    for (let i = bytes.length - 1; i > -1; i--) {
        n = n.shiftLeft(8).or(bi('' + bytes[i]));
    }
    return n;
}

export function hex2bi(s: string): BigInteger {
    return new BigInteger(s, 16);
}


export function concatUint8Arrays(uint8Arrays: Uint8Array[]): Uint8Array {
    let concatenatedArrayLength = 0;

    uint8Arrays.forEach(arr => {
        concatenatedArrayLength += arr.length;
    })

    let concatenatedArray = new Uint8Array(concatenatedArrayLength);

    for (let i = 0, startingLengthOfSetOp = 0; i < uint8Arrays.length; i++) {
        if (i === 0) {
            concatenatedArray.set(uint8Arrays[0])
        } else {
            startingLengthOfSetOp += uint8Arrays[i - 1].length
            concatenatedArray.set(uint8Arrays[i], startingLengthOfSetOp)
        }
    }

    return concatenatedArray
}


declare module 'jsbn' {
    interface BigInteger {
        times: typeof BigInteger.prototype.multiply
        plus: typeof BigInteger.prototype.add
        minus: typeof BigInteger.prototype.subtract
        square(): BigInteger
        lesser(a: BigInteger): boolean
        greater(a: BigInteger): boolean
        greaterOrEqualTo(a: BigInteger): boolean
        lesserOrEqualTo(a: BigInteger): boolean
        lesserThan: typeof BigInteger.prototype.lesser
        greaterThan: typeof BigInteger.prototype.greater
        equalTo: typeof BigInteger.prototype.equals
    }
}

BigInteger.prototype.times = BigInteger.prototype.multiply;
BigInteger.prototype.plus = BigInteger.prototype.add;
BigInteger.prototype.minus = BigInteger.prototype.subtract;
BigInteger.prototype.square = function () {
    return this.times(this);
};
BigInteger.prototype.lesser = function (a) {
    return (this.compareTo(a) < 0);
};
BigInteger.prototype.greater = function (a) {
    return (this.compareTo(a) > 0);
};
BigInteger.prototype.greaterOrEqualTo = function (a) {
    return (this.compareTo(a) >= 0);
};
BigInteger.prototype.lesserOrEqualTo = function (a) {
    return (this.compareTo(a) >= 0);
};
BigInteger.prototype.lesserThan = BigInteger.prototype.lesser;
BigInteger.prototype.greaterThan = BigInteger.prototype.greater;
BigInteger.prototype.equalTo = BigInteger.prototype.equals;

export { BigInteger }

// BigInteger construction done right
export function bi(s: string | number | Uint8Array, base?: number): BigInteger {
  if (typeof base !== 'undefined') {
      if (base === 256) return bytes2bi(string2bytes(s as string));
      return new BigInteger(s as any, base);
  } else if (typeof s === 'string') {
      return new BigInteger(s, 10);
  } else if (s instanceof Uint8Array) {
      return bytes2bi(s);
  } else if (typeof s === 'number') {
      return new BigInteger(s.toString(), 10);
  } else {
      throw new Error(`Can't convert ${s} to BigInteger`);
  }
}

export const zero = BigInteger.ZERO;
export const one = BigInteger.ONE;
export const two = bi('2');
