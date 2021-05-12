// Written in the D Programming Language

module stdx.digest.siphash;

import std.algorithm;
import std.traits;
import std.string;
import std.meta;
import std.range;
import std.conv;
import std.typecons;
import std.format;
import std.bitmanip;

import core.bitop : rol;

import std.digest : isDigest, hasBlockSize, DigestType;

// version = SipHashDebug;
version (SipHashDebug) {
    import std.stdio;

    void dumpv(T)(T[4] v, string msg) {
        writeln(msg);
        writefln("v0 = %0" ~ T.sizeof.to!string ~ "x", v[0]);
        writefln("v1 = %0" ~ T.sizeof.to!string ~ "x", v[1]);
        writefln("v2 = %0" ~ T.sizeof.to!string ~ "x", v[2]);
        writefln("v3 = %0" ~ T.sizeof.to!string ~ "x", v[3]);
    }
}


@safe:

private  T xor(T, bool Half = false)(ref T[4] v) @safe if (is(T == uint) || is(T == ulong)) {
    static if (Half) { return v[1] ^ v[3]; }
    else { return v[0] ^ v[1] ^ v[2] ^ v[3]; }
}


private auto round(size_t roundCount, T)(ref T[4] v) if (is(T == uint) || is(T == ulong)) {
    static if (is(T == ulong)) {
        enum rolWidth = AliasSeq!(13, 32, 16, 21, 17, 32);
    }
    else {
        enum rolWidth = AliasSeq!(5, 16, 8, 7, 13, 16);
    }

    static foreach (i; 0..roundCount) {
        v[0] += v[1];
        v[1] = rol(v[1], rolWidth[0]);
        v[1] ^= v[0];
        v[0] = rol(v[0], rolWidth[1]);
        v[2] += v[3];
        v[3] = rol(v[3], rolWidth[2]);
        v[3] ^= v[2];

        v[0] += v[3];
        v[3] = rol(v[3], rolWidth[3]);
        v[3] ^= v[0];
        v[2] += v[1];
        v[1] = rol(v[1], rolWidth[4]);
        v[1] ^= v[2];
        v[2] = rol(v[2], rolWidth[5]);
    }
}

private T[2] readKey(T)(scope const(ubyte)[] key) @trusted if (is(T == uint) || is(T == ulong)) {
    assert(key.length == 2 * T.sizeof);
    size_t offset = 0;
    T k0 = key.peek!(T, Endian.littleEndian)(0);
    T k1 = key.peek!(T, Endian.littleEndian)(T.sizeof);
    return [k0, k1];
}


///
template siphash(T, size_t length = 64, size_t cround = 2, size_t dround = 4) {
    static assert (is(T == uint) || is(T == ulong), T.stringof ~ " not accept");

    static if (is(T == ulong)) {
        static assert (length == 64 || length == 128,  "cannot accept " ~ T.stringof ~ " with length = " ~ length.stringof);
        static if (length == 64) {
            alias R = T[1];
        }
        else {
            alias R = T[2];
        }
        enum KN = 16;
        enum Large = length == 128;
        enum Half = false;
        enum V = [ cast(ulong)0x736f6d6570736575, 0x646f72616e646f6d, 0x6c7967656e657261, 0x7465646279746573 ];
        enum LSHIFT = 56;
    }
    else {
        static assert (length == 32 || length == 64,  "cannot accept length = " ~ T.stringof);
        static if (length == 32) {
            alias R = T[1];
        }
        else {
            alias R = T[2];
        }
        enum KN = 8;
        enum Large = length == 64;
        enum Half = true;
        enum V = [ cast(uint)0, 0, 0x6c796765, 0x74656462 ];
        enum LSHIFT = 24;
    }


    auto tryPeek(const ubyte[] data, ref size_t offset, ref T value) @trusted {
        if (offset + T.sizeof <= data.length) {
            value = data.peek!(T, Endian.littleEndian)(offset);
            offset += T.sizeof;
            return true;
        }
        else {
            return false;
        }
    }

    R siphash(const ubyte[KN] key, const ubyte[] data) @safe {
        auto k = readKey!T(key);

        T[4] v = [ V[0] ^ k[0], V[1] ^ k[1], V[2] ^ k[0], V[3] ^ k[1] ];
        static if (Large) {
            v[1] ^= 0xee;
        }

        version(SipHashDebug)
            writefln("-- prepare (%s%s - 0:%016x 1:%016x) : [%(%02x, %)]", length, Half?" half":"", k[0], k[1], data);

        T m;
        size_t offset = 0;
        while(tryPeek(data, offset, m)) {
            v[3] ^= m;
            round!(cround, T)(v);
            v[0] ^= m;
        }

        m = cast(T)data.length << LSHIFT;
        static foreach (i; 0..T.sizeof-1) {
            if (offset < data.length) {
                m |= cast(ulong)data[offset] << 8*i;
                offset++;
            }
        }
        assert(data.length == offset, "length %s == offset %s".format(data.length, offset));

        version(SipHashDebug) dumpv(v, "-- rest");
        v[3] ^= m;
        round!(cround, T)(v);
        v[0] ^= m;

        static if (Large) {
            v[2] ^= 0xee;
        }
        else {
            v[2] ^= 0xff;
        }

        version(SipHashDebug) dumpv(v, "-- dr");
        round!(dround, T)(v);

        version(SipHashDebug) dumpv(v, "-- endup");
        R r;
        r[0] = xor!(T, Half)(v);
        version(SipHashDebug) writeln(r[0]);
        static if (Large) {
            v[1] ^= 0xdd;
            round!(dround, T)(v);
            r[1] = xor!(T, Half)(v);
        }
        return r;

    }
}


/// aliases for usability
alias siphashOf = siphash!(ulong, 64, 2, 4);
/// ditto
alias siphash128Of = siphash!(ulong, 128, 2, 4);
/// ditto
alias siphash32Of = siphash!(uint, 32, 2, 4);
/// ditto
alias siphash64Of = siphash!(uint, 64, 2, 4);

/// siphash 2-4-64
unittest {
    ubyte[16] key;
    auto r = siphashOf(key, "foobar".representation);

    assert(is(typeof(r) == ulong[1]));
    assert(r[0] == 0xaac7cb99d530deb);
}

/// ditto
unittest {
    auto key = "0123456789ABCDEF".representation.array;
    assert(key.length == 16);
    auto r = siphashOf(key[0..16], "foobar".representation);

    assert(r[0] == 0xf3afaa0fb365996e);
}

/// ditto
unittest {
    ubyte[16] key;
    ubyte[] data = repeat(cast(ubyte)0, 64).array;
    auto r = siphashOf(key, data);

    assert(r[0] == 0x4ec86d89f765eab5);
}

/// siphash 2-4-128 (double)
unittest {
    ubyte[16] key;
    auto r = siphash128Of(key, "foobar".representation);

    assert(is(typeof(r) == ulong[2]));
    assert(r[0] == 0x70a9376692334138);
    assert(r[1] == 0x66a48f012b6a4707);
}

/// ditto
unittest {
    auto key = "0123456789ABCDEF".representation.array;
    assert(key.length == 16);
    auto r = siphash128Of(key[0..16], "foobar".representation);

    assert(r[0] == 0xafb4eae7623b012a);
    assert(r[1] == 0x3d666d0dc9027b1b);

}

/// ditto
unittest {
    ubyte[16] key;
    ubyte[] data = repeat(cast(ubyte)0, 64).array;
    auto r = siphash128Of(key, data);

    assert(r[0] == 0xf8bf0de799b3eb9a);
    assert(r[1] == 0x684386e11ffea028);
}

unittest {
    auto r = siphashOf("0123456789ABCDEF".representation[0 .. 16], "Hello, World".representation);
    assert(r[0] == 0x6252e47fb397fdff);
}


/**
 * Get hash of SipHash with isDigest compatibility.
 */
struct SipHash(T, size_t length = 64, size_t cround = 2, size_t dround = 4) if (is(T == uint) || is(T == ulong)) {
    static const ubyte[2 * T.sizeof] Zero = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0][0 .. 2 * T.sizeof];

private:
    static if (is(T == uint)) {
        static if (length == 32) {
            enum VN = 1;
            enum Large = false;
        }
        else {
            enum VN = 2;
            enum Large = true;
        }
        enum KN = 8;
        enum Half = true;
        enum V = [ cast(uint)0, 0, 0x6c796765, 0x74656462 ];
    }
    else static if (is(T == ulong)) {
        static if (length == 64) {
            enum VN = 1;
            enum Large = false;
        }
        else {
            enum VN = 2;
            enum Large = true;
        }
        enum KN = 16;
        enum Half = false;
        enum V = [ cast(ulong)0x736f6d6570736575, 0x646f72616e646f6d, 0x6c7967656e657261, 0x7465646279746573 ];
    }
    else static assert(0);

    public const T[2] key;
    T[4] _value;
    ubyte[T.sizeof] _buf;
    size_t _offset;
    size_t _length;

    void round(ref T mod) {
        _value[3] ^= mod;
        .round!(cround, T)(_value);
        _value[0] ^= mod;
    }

    auto tryPeek(const(ubyte)[] data, ref size_t offset, ref T value) @trusted {
        if (offset + T.sizeof <= data.length) {
            value = data.peek!(T, Endian.littleEndian)(offset);
            offset += T.sizeof;
            return true;
        }
        else { return false; }
    }

public @trusted:
    /**
     * Construct the SipHash digest.
     */
    this(const ubyte[KN] key) {
        this.key[] = readKey!T(key);
        start();
    }

    /**
     * Constructs the SipHash digest using any string.
     * if key is 16 bytes long, use it as a key.
     * otherwise, the key is convert to 128bit-hashed with Zero-Key.
     * Example:
     * ----
     * newkey = sipHash128Of(Zero, key.representation);
     * ----
     *
     */
    this(string key) {
        if (key.length == 2 * T.sizeof) {
            this.key[] = readKey!T(key.representation);
        }
        else {
            static if (Half) {
                this.key = siphash64Of(Zero, key.representation);
            }
            else {
                this.key = siphash128Of(Zero, key.representation);
            }
        }
        start();
    }

    ///
    unittest {
        auto hash = SipHash!(ulong)("0123456789ABCDEF");
        hash.put("Hello, World".representation);
        auto r = hash.finish();
        assert(r == 0x6252e47fb397fdff.nativeToLittleEndian(), "%(%02x, %)".format(r));

        hash.put("Hello, ".representation);
        hash.put("World".representation);
        auto r2 = hash.finish();
        assert(r[0] == r2[0], "%016x == %016x".format(r[0], r2[0]));
    }


    /**
     * (Re) initialize the digest.
     *
     */
    void start() {
        _offset = 0;
        _length = 0;
        _value[] = [ V[0] ^ key[0], V[1] ^ key[1], V[2] ^ key[0], V[3] ^ key[1] ];
        static if (Large) {
            _value[1] ^= 0xee;
        }
        version(SipHashDebug) writefln("init: [%(%02x, %)] <= key: [%016x, %016x]", _value, key[0], key[1]);
    }

    import std.stdio;
    /**
     * feed data to siphash digest.
     */
    void put(scope const(ubyte)[] data...) {
        T m;
        size_t offset = 0;
        if (_offset > 0) {
            offset = min(T.sizeof - _offset, data.length);
            _buf[_offset.._offset + offset] = data[0..offset];
            if (_offset + offset == T.sizeof) { 
                size_t x = 0;
                tryPeek(_buf, x, m);
                round(m);
                _offset = 0;
            }
            else {
                _offset += offset;
            }
        }

        while (tryPeek(data, offset, m)) {
            round(m);
        }

        if (offset != data.length) {
            const l = data.length - offset;
            _buf[_offset.._offset+l] = data[offset..$];
            _offset += l;
        }

        _length += data.length;
    }

    /**
     * Get result and Reset the hash.
     */
    ubyte[VN * T.sizeof] finish() {
        T m = cast(T)_length << 8*(T.sizeof - ubyte.sizeof);
        if (_offset > 0) {
            size_t o;

            T v;
            _buf[_offset..$] = 0;
            tryPeek(_buf, o, v);
            m |= v;
        }
        version(SipHashDebug) dumpv(_value, "-- rest");
        round(m);

        static if (Large) {
            _value[2] ^= 0xee;
        }
        else {
            _value[2] ^= 0xff;
        }

        version(SipHashDebug) dumpv(_value, "-- dr");
        .round!(dround, T)(_value);


        T r;
        ubyte[VN * T.sizeof] res;
        r = xor!(T, Half)(_value);
        res[0..T.sizeof] = nativeToLittleEndian(r);
        version(SipHashDebug) writeln(r);
        static if (Large) {
            _value[1] ^= 0xdd;
            .round!(dround, T)(_value);
            r = xor!(T, Half)(_value);
            res[T.sizeof..$] = nativeToLittleEndian(r);
        }

        this.start();
        return res;
    }
}

///
unittest {
    assert(isDigest!(SipHash!ulong));
}

///
unittest {
    auto hash = SipHash!ulong();
    hash.start();
    hash.put("foo".representation);
    hash.put("bar".representation);
    auto r = hash.finish();
    assert(is(typeof(r) == ubyte[8]));
    auto expect = nativeToLittleEndian(0x0aac7cb99d530deb);
    assert(r == expect, format("%(%02x, %)", r));
}


/// ditto
unittest {
    auto hash = SipHash!ulong("0123456789ABCDEF".representation.array[0..16]);
    hash.start();
    hash.put("foo".representation);
    hash.put("bar".representation);

    auto r = hash.finish();
    assert(r == 0xf3afaa0fb365996e.nativeToLittleEndian);
}

/// ditto
unittest{
    auto hash = SipHash!(ulong)();
    hash.start();
    hash.put(repeat(cast(ubyte)0, 64).array);

    auto r = hash.finish();
    assert(r == 0x4ec86d89f765eab5.nativeToLittleEndian);
}

/// siphash 2-4-128 (double)
unittest {
    auto hash = SipHash!(ulong, 128)();
    hash.start();
    hash.put("foo".representation);
    hash.put("bar".representation);
    auto r = hash.finish();
    assert(r[0..8] == 0x70a9376692334138.nativeToLittleEndian());
    assert(r[8..$] == 0x66a48f012b6a4707.nativeToLittleEndian());
}

/// ditto
unittest {
    auto hash = SipHash!(ulong, 128)("0123456789ABCDEF".representation.array[0..16]);
    hash.start();
    hash.put("foobar".representation);

    auto r = hash.finish();
    assert(r[0..8] == 0xafb4eae7623b012a.nativeToLittleEndian);
    assert(r[8..$] == 0x3d666d0dc9027b1b.nativeToLittleEndian);
}

/// ditto
unittest {
    auto hash = SipHash!(ulong, 128)();
    hash.start();
    hash.put(repeat(cast(ubyte)0, 64).array);

    auto r = hash.finish();
    assert(r[0..8] == 0xf8bf0de799b3eb9a.nativeToLittleEndian);
    assert(r[8..$] == 0x684386e11ffea028.nativeToLittleEndian);
}




