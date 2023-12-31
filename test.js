var buffer = require('buffer');
var crypto = require('crypto');
var assert = require('assert');

var INITIAL_SECRET = Buffer.from('ef4fb0abb47470c41befcf8031334fae485e09a0', 'hex');
var SHA256 = 'sha256';
var AES_GCM = 'aes-128-gcm';
var AES_ECB = 'aes-128-ecb';

function log(m, k) {
  console.log(m + ' [' + k.length + ']: ' + k.toString('hex'));
};

/* HKDF as defined in RFC5869. */
class HMAC {
  constructor(hash) {
    this.hash = hash;
  }

  digest(key, input) {
    var hmac = crypto.createHmac(this.hash, key);
    hmac.update(input);
    return hmac.digest();
  }
}

class QHKDF {
  constructor(hmac, prk) {
    this.hmac = hmac;
    this.prk = prk;
  }

  static extract(hash, salt, ikm) {
    var hmac = new HMAC(hash);
    return new QHKDF(hmac, hmac.digest(salt, ikm));
  }

  expand(info, len) {
    var output = Buffer.alloc(0);
    var T = Buffer.alloc(0);
    info = Buffer.from(info, 'ascii');
    var counter = 0;
    var cbuf = Buffer.alloc(1);
    while (output.length < len) {
      cbuf.writeUIntBE(++counter, 0, 1);
      T = this.hmac.digest(this.prk, Buffer.concat([T, info, cbuf]));
      output = Buffer.concat([output, T]);
    }

    return output.slice(0, len);
  }

  expand_label(label, len) {
    var baseLabel = "tls13 ";
    var info = Buffer.alloc(2 + 1 + baseLabel.length + label.length + 1);
    // Note that Buffer.write returns the number of bytes written, whereas
    // Buffer.writeUIntBE returns the end offset of the write.  Consistency FTW.
    var offset = info.writeUIntBE(len, 0, 2);
    offset = info.writeUIntBE(baseLabel.length + label.length, offset, 1);
    offset += info.write(baseLabel + label, offset);
    info.writeUIntBE(0, offset, 1);
    // log('info for ' + label, info);
    return this.expand(info, len);
  }
}

class InitialProtection {
  constructor(label, cid) {
    var qhkdf = QHKDF.extract(SHA256, INITIAL_SECRET, cid);
    // log('initial_secret', qhkdf.prk);
    qhkdf = new QHKDF(qhkdf.hmac, qhkdf.expand_label(label, 32));
    // log(label + ' secret', qhkdf.prk);
    this.key = qhkdf.expand_label("quic key", 16);
    // log(label + ' key', this.key);
    this.iv = qhkdf.expand_label("quic iv", 12);
    // log(label + ' iv', this.iv);
    this.pn = qhkdf.expand_label("quic hp", 16);
    // log(label + ' pn', this.pn);
  }

  generateNonce(counter) {
    var nonce = Buffer.from(this.iv);
    var m = nonce.readUIntBE(nonce.length - 6, 6);
    var x = ((m ^ counter) & 0xffffff) +
        ((((m / 0x1000000) ^ (counter / 0x1000000)) & 0xffffff) * 0x1000000);
    nonce.writeUIntBE(x, nonce.length - 6, 6);
    return nonce;
  }

  // Returns the encrypted data with authentication tag appended.  The AAD is
  // used, but not added to the output.
  encipher(pn, aad, data) {
    // console.log('encipher pn', pn);
    // log('encipher aad', aad);
    // log('encipher data', data);
    var nonce = this.generateNonce(pn);
    var gcm = crypto.createCipheriv(AES_GCM, this.key, nonce);
    gcm.setAAD(aad);
    var e = gcm.update(data);
    gcm.final();
    e = Buffer.concat([e, gcm.getAuthTag()]);
    // log('enciphered', e);
    return e;
  }

  decipher(pn, aad, data) {
    // console.log('decipher pn', pn);
    log('decipher aad', aad);
    log('decipher data', data);
    var nonce = this.generateNonce(pn);
    var gcm = crypto.createDecipheriv(AES_GCM, this.key, nonce);
    gcm.setAAD(aad);
    gcm.setAuthTag(data.slice(data.length - 16));
    var d = gcm.update(data.slice(0, data.length - 16));
    gcm.final();
    // log('deciphered', d);
    return d;
  }

  // Calculates the packet number encryption mask.
  pneMask(sample) {
   // sample = Buffer.from('c2973fa0d63fd9b03a4e163b990dd778', 'hex');
    // log('pne sample', sample);
    // var ctr = crypto.createCipheriv('aes-128-ctr', this.pn, sample);
    // var mask = ctr.update(Buffer.alloc(5));
    var ecb = crypto.createCipheriv('aes-128-ecb', this.pn, Buffer.alloc(0));
    var mask = ecb.update(sample);
    // log('pne mask', mask);
    return mask;
  }

  // XOR b into a.
  xor(a, b) {
    a.forEach((_, i) => {
      a[i] ^= b[i];
    });
  }

  // hdr is everything before the length field
  // hdr[0] has the packet number length already in place
  // pn is the packet number
  // data is the payload (i.e., encoded frames)
  encrypt(hdr, pn, data) {
    var pn_len = 1 + (hdr[0] & 0x3);
    assert(pn_len + data.length >= 4);

    var aad = Buffer.alloc(hdr.length + 2 + pn_len);
    var offset = hdr.copy(aad);
    // Add a length that covers the packet number encoding and the auth tag.
    offset = aad.writeUIntBE(0x4000 | (pn_len + data.length + 16), offset, 2);
    var pn_offset = offset;
    var pn_mask = 0xffffffff >> (8 * (4 - pn_len));
    offset = aad.writeUIntBE(pn & pn_mask, offset, pn_len)
    // log('header', aad);

    var payload = this.encipher(pn, aad, data);

    var mask = this.pneMask(payload.slice(4 - pn_len, 20 - pn_len));
    aad[0] ^= mask[0] & (0x1f >> (aad[0] >> 7));
    this.xor(aad.slice(pn_offset), mask.slice(1));
    // log('masked header', aad);
    return Buffer.concat([aad, payload]);
  }

  cidLen(v) {
    if (!v) {
      return 0;
    }
    return v + 3;
  }

  decrypt(data) {
    // log('decrypt', data);
    if (data[0] & 0x40 != 0x40) {
      throw new Error('missing QUIC bit');
    }
    if (data[0] & 0x80 == 0) {
      throw new Error('short header unsupported');
    }
    var hdr_len = 1 + 4 + 1 +
        this.cidLen(data[5]&0xf) + this.cidLen(data[5]>>4);
    if ((data[0] & 0x30) == 0) { // Initial packet.
      hdr_len += 1 + data[hdr_len];  // oops: this only handles single octet lengths.
    }
    // Skip the length.
    hdr_len += 1 << (data[hdr_len] >> 6);
    // Now we're at the encrypted bit.
    var mask = this.pneMask(data.slice(hdr_len + 4, hdr_len + 20));

    var octet0 = data[0] ^ (mask[0] & (0x1f >> (data[0] >> 7)));
    var pn_len = (octet0 & 3) + 1;
    var hdr = Buffer.from(data.slice(0, hdr_len + pn_len));
    hdr[0] = octet0;
    // log('header', hdr);
    this.xor(hdr.slice(hdr_len), mask.slice(1));
    console.log(hdr_len, pn_len, hdr.readUIntBE(hdr_len, pn_len))
    var pn = hdr.readUIntBE(hdr_len, pn_len);
    // TODO recover PN based on expected value.
    return this.decipher(pn, hdr, data.slice(hdr.length));
  }
}

function pad(hdr, body) {
  var pn_len = (hdr[0] & 3) + 1;
  var size = 1200 - hdr.length - 2 - pn_len - 16; // Assume 2 byte length.
  if (size < 0) {
    return body;
  }
  var padded = Buffer.allocUnsafe(size);
  // console.log('pad amount', size);
  body.copy(padded);
  padded.fill(0, body.length);
  // log('padded', padded);
  return padded;
}

function test(role, cid, hdr, pn, body) {
  cid = Buffer.from(cid, 'hex');
  // log('connection ID', cid);
  hdr = Buffer.from(hdr, 'hex');
  // log('header', hdr);
  // console.log('packet number = ' + pn);
  body = Buffer.from(body, 'hex');
  // log('body', hdr);

  if (role === 'client' && (hdr[0] & 0x30) === 0) {
    body = pad(hdr, body);
  }

  var endpoint = new InitialProtection(role + ' in', cid);
  var packet = endpoint.encrypt(hdr, pn, body);
  // log('encrypted packet', packet);

  var content = endpoint.decrypt(packet);
  // log('decrypted content', content);
  // assert(content.compare(body) == 0);
}

var version = 'ff000011'
var cid = '06b858ec6f80452b';
var initial_hdr = 'c3' + version + '50' + cid + '00';
var short_pn_hdr = 'c1' + version + '50' + cid + '00';

// This should be a valid server Initial.
var frames = '0d0000000018410a' +
    '020000560303eefce7f7b37ba1d163' +
    '2e96677825ddf73988cfc79825df566dc5430b9a04' +
    '5a1200130100002e00330024001d00209d3c940d89' +
    '690b84d08a60993c144eca684d1081287c834d5311' +
    'bcf32bb9da1a002b00020304';
test('server', cid, initial_hdr, 0, frames);
test('server', cid, short_pn_hdr, 1, frames);

// This is a valid client Initial.  I think.
var crypto_frame = '060040c4' +
    '010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba14131a0e8' +
    'f309a1d0b9c4000006130113031302010000910000000b000900000673657276' +
    '6572ff01000100000a00140012001d0017001800190100010101020103010400' +
    '230000003300260024001d00204cfdfcd178b784bf328cae793b136f2aedce00' +
    '5ff183d7bb1495207236647037002b0003020304000d0020001e040305030603' +
    '020308040805080604010501060102010402050206020202002d00020101001c' +
    '00024001';
test('client', cid, initial_hdr, 0, crypto_frame);