const jsbn = require('jsbn');

const BigInteger = jsbn.BigInteger;

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
BigInteger.prototype.equals = function (a) {
    return (this.compareTo(a) == 0);
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

// BigInteger construction done right
function bi(s, base) {
  if (base != undefined) {
      if (base == 256) return bytes2bi(string2bytes(s));
      return new BigInteger(s, base);
  } else if (typeof s == 'string') {
      return new BigInteger(s, 10);
  } else if (s instanceof Array) {
      return bytes2bi(s);
  } else if (typeof s == 'number') {
      return new BigInteger(s.toString(), 10);
  } else {
      throw "Can't convert " + s + " to BigInteger";
  }
}

const zero = BigInteger.ZERO;
const one = BigInteger.ONE;
const two = bi('2');

module.exports = {
  bi,
  zero,
  one,
  two,
}