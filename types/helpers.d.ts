import { BigInteger } from 'jsbn';
export declare function bytes2string(bytes: Uint8Array): string;
export declare function string2bytes(s: string): Uint8Array;
export declare function bi2bytes(n: any, cnt: number): Uint8Array;
export declare function bytes2bi(bytes: Uint8Array): BigInteger;
export declare function hex2bi(s: string): BigInteger;
export declare function concatUint8Arrays(uint8Arrays: Uint8Array[]): Uint8Array;
declare module 'jsbn' {
    interface BigInteger {
        times: typeof BigInteger.prototype.multiply;
        plus: typeof BigInteger.prototype.add;
        minus: typeof BigInteger.prototype.subtract;
        square(): BigInteger;
        lesser(a: BigInteger): boolean;
        greater(a: BigInteger): boolean;
        greaterOrEqualTo(a: BigInteger): boolean;
        lesserOrEqualTo(a: BigInteger): boolean;
        lesserThan: typeof BigInteger.prototype.lesser;
        greaterThan: typeof BigInteger.prototype.greater;
        equalTo: typeof BigInteger.prototype.equals;
    }
}
export { BigInteger };
export declare function bi(s: string | number | Uint8Array, base?: number): BigInteger;
export declare const zero: BigInteger;
export declare const one: BigInteger;
export declare const two: BigInteger;
