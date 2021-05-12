# digest_siphash
[SipHash](https://github.com/veorq/SipHash) on D

## Usage

### template function call
```d
import std.string : representation;
import digest.siphash;

...

ubyte[16] key = "0123456789ABCDEF".representation[0 .. 16];
ubyte[] data = "foobar".representation;

ulong r64 = siphash!(ulong, 64)(key, data); // SipHash 2-4 64bit
ulong[2] r128 = siphash!(ulong, 128)(key, data); // SipHash 2-4 128bit
uint h32 = siphash!(uint, 32)(key, data); // SipHash Half 2-4 32bit
uint[2] h64 = siphash!(uint, 64)(key, data); // SipHash Half 2-3 64bit
```

### Digest ([std.digest](https://dlang.org/phobos/std_digest.html)) call
```d
import std.digest : isDigest;
import std.string : representaion;
import digest.siphash;
...

assert(isDigest!(SipHash!ulong));
auto hash = SipHash!ulong(); // SipHash2-4 64bit with key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
hash.put("somedata".representation);
ulong[2] r = hash.finish();
```

#### variant
- SipHash2-4 128bit = `SipHash!(ulong, 128)`
  * result type = `ulong[2]`
- SipHash2-4 64bit = `SipHash!(ulong, 64)`
  * result type = `ulong[1]`
- SipHash Half 2-4 64bit = `SipHash!(uint, 64)`
  * result type = `uint[2]`
- SipHash Half 2-4 32bit = `SipHash!(uint, 32)`
  * result type = `uint[1]`

#### constructor argument
```d
SipHash!(T)(scope const(ubyte)[16] key);
SipHash!(T)(string key);
```
if `string key` is 16bytes, use it as `const(ubyte)[16]`.
otherwise, use with hashing with empty key `[0, 0, ...]`.

## TODO

- [ ] improve api
- [ ] improve document
- [ ] write unittest

