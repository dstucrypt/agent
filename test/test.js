const assert = require('assert');
const fs = require('fs');

const agent = require('../agent');

function asset(name) {
  return `${__dirname}/../node_modules/jkurwa/test/data/${name}`;
}

class IOBuffer {
  constructor() {
    this.buffer = []
  };

  write(piece) {
    this.buffer.push(piece);
  }
}

function getIO() {
  const assets = {};
  return {
    stdout: new IOBuffer(),
    stderr: new IOBuffer(),
    asset: function(filename, contents) {
      assets[`/dev/null/${filename}`] = contents || this.readAsset(filename) || Buffer.alloc(0);
      return `/dev/null/${filename}`;
    },
    readFileSync: function(filename) {
      return assets[filename] || fs.readFileSync(filename);
    },
    readAsset: function(filename) {
      return assets[`/dev/null/${filename}`];
    },
    writeFileSync: function(filename, contnets) {
      if (assets[filename]) {
        assets[filename] = contnets;
      } else {
        return fs.readFileSync(filename);
      }
    },
  };
}

describe('Local Agent', ()=> {
  describe('encypted p7s', ()=> {
    it('Decryption success', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.p7'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_40A0.cer'),
          asset('SELF_SIGNED_ENC_6929.cer')
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('123')]);
      assert.deepEqual(io.stderr.buffer, ['Encrypted']);
    });

    it('Decryption error when own cert is not supplied', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.p7'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_6929.cer')
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ['Error occured during unwrap: ENOKEY']);
    });

    it("Decryption error when sender cert is not supplied", ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.p7'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_40A0.cer')
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ['Encrypted', 'Error occured during unwrap: ENOCERT']);
    });
  });

  describe('encypted transport', ()=> {
    it('Decrypt data', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.transport'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_40A0.cer'),
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('123')]);
      assert.deepEqual(io.stderr.buffer, ['Encrypted']);
    });

    it('Decrypt and write cleartext to file', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.transport'),
        output: io.asset('clear.txt'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_40A0.cer'),
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ['Encrypted']);
      assert.deepEqual(io.readAsset('clear.txt'), Buffer.from('123'));
    });

    it('Decryption error when own cert is not supplied', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('enc_message.transport'),
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_6929.cer')
        ],
      }, io);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ['Error occured during unwrap: ENOKEY']);
    });
  });

  describe('signed p7s', ()=> {
    it('check signature', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('message.p7'),
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('123')]);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
    });

    it('check signature and write cleatext to file', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('message.p7'),
        output: io.asset('clear.txt'),
      }, io);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
      assert.deepEqual(io.readAsset('clear.txt'), Buffer.from('123'));
    });

  });

  describe('signed transport', ()=> {
    it('check signature', ()=> {
      const io = getIO();
      agent.run({
        decrypt: true,
        input: asset('message.transport'),
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('123')]);
      assert.deepEqual(io.stderr.buffer, ['Sent-By-EDRPOU:', '1234567891', 'Signed-By:', 'Very Much CA']);
    });
  });

  describe('sign and unwrap', ()=> {
    it('check signature', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: io.asset('signed.p7s'),
        output: io.asset('signed.p7s'),
      }, io);
      const signed = io.readAsset('signed.p7s');
      assert.equal(signed[0], 0x30);

      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s'),
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
    });

    it('check signature with transport container', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        tax: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: io.asset('signed.p7s', true),
      }, io);

      const signed = io.readAsset('signed.p7s');
      assert.deepEqual(signed.slice(0, 9).toString(), 'UA1_SIGN\0');

      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s'),
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
    });

    it('check signature with transport container including headers', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        tax: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: io.asset('signed.p7s'),
        email: 'username@email.example.com',
        edrpou: '1234567891',
      }, io);

      const signed = io.readAsset('signed.p7s');
      assert.deepEqual(signed.slice(0, 14).toString(), 'TRANSPORTABLE\0');

      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s'),
      }, io);
      assert.deepEqual(io.stderr.buffer, [
        'Filename:', 'clear.txt',
        'Sent-By-EDRPOU:', '1234567891',
        'Signed-By:', 'Very Much CA'
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
    });

    it('write signature to stdout and decode cp1251 is specified in headers', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        encode_win: true,
        tax: true,
        email: 'username@email.example.com',
        edrpou: '1234567891',
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me. ЖчССТБ!')),
        output: '-',
      }, io);

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s', signed),
      }, io);
      assert.deepEqual(io.stderr.buffer, [
        'Filename:', 'clear.txt',
        'Sent-By-EDRPOU:', '1234567891',
        'Signed-By:', 'Very Much CA'
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me. ЖчССТБ!')]);
    });

    it('write signature to file without decoding content', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        encode_win: true,
        tax: true,
        email: 'username@email.example.com',
        edrpou: '1234567891',
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me. ЖчССТБ!')),
        output: '-',
      }, io);

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s', signed),
        output: io.asset('clear_out.txt'),
      }, io);
      assert.deepEqual(io.stderr.buffer, [
        'Filename:', 'clear.txt',
        'Sent-By-EDRPOU:', '1234567891',
        'Signed-By:', 'Very Much CA'
      ]);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(
        io.readAsset('clear_out.txt'),
        Buffer.from('This is me. \xC6\xF7\xD1\xD1\xD2\xC1!', 'binary')
      );
    });

    it('write signature to stdout', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: '-',
      }, io);

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s', signed),
      }, io);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
    });

    it('write detached signature to stdout and fail with ENODATA on parse', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        detached: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: '-',
      }, io);

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s', signed),
      }, io);
      assert.deepEqual(io.stderr.buffer, ['Error occured during unwrap: ENODATA']);
      assert.deepEqual(io.stdout.buffer, []);
    });

    it('write detached signature to stdout and supply two files when parsing', ()=> {
      const io = getIO();
      agent.run({
        sign: true,
        detached: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: '-',
      }, io);

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      agent.run({
        decrypt: true,
        input: [
          io.asset('signed.p7s', signed),
          io.asset('clear.txt', Buffer.from('This is me')),
        ],
      }, io);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
    });

  });

  describe('encrypt and decrypt', ()=> {
    it('check signature and decrypt', ()=> {
      const io = getIO();
      agent.run({
        tax: true,
        crypt: asset('SELF_SIGNED_ENC_40A0.cer'),
        key: [asset('Key6929.cer'), asset('PRIV1.cer')],
        cert: [asset('SELF_SIGNED_ENC_6929.cer'), asset('SELF_SIGNED1.cer')],
        input: io.asset('clear.txt', Buffer.from('This was encrypted')),
        output: io.asset('encrypted.p7s'),
      }, io);

      agent.run({
        decrypt: true,
        input: io.asset('encrypted.p7s'),
        key: asset('Key40A0.cer'),
        cert: asset('SELF_SIGNED_ENC_40A0.cer'),
      }, io);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA', 'Encrypted']);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This was encrypted')]);
    });

    it('encrypts when recipient is specified with --recipient_cert', ()=> {
      const io = getIO();
      agent.run({
        tax: true,
        crypt: true,
        'recipient_cert': asset('SELF_SIGNED_ENC_40A0.cer'),
        key: [asset('Key6929.cer'), asset('PRIV1.cer')],
        cert: [asset('SELF_SIGNED_ENC_6929.cer'), asset('SELF_SIGNED1.cer')],
        input: io.asset('clear.txt', Buffer.from('This was encrypted')),
        output: io.asset('encrypted.p7s'),
      }, io);

      agent.run({
        decrypt: true,
        input: io.asset('encrypted.p7s'),
        key: asset('Key40A0.cer'),
        cert: asset('SELF_SIGNED_ENC_40A0.cer'),
      }, io);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA', 'Encrypted']);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This was encrypted')]);
    });

    it('should fail when encryption recipient not specified', ()=> {
      const io = getIO();
      agent.run({
        tax: true,
        crypt: true,
        key: [asset('Key6929.cer'), asset('PRIV1.cer')],
        cert: [asset('SELF_SIGNED_ENC_6929.cer'), asset('SELF_SIGNED1.cer')],
        input: io.asset('clear.txt', Buffer.from('This was encrypted')),
        output: io.asset('encrypted.p7s'),
      }, io);

      assert.deepEqual(io.stderr.buffer, ['Please specify recipient certificate for encryption mode: --crypt filename.cert']);
      assert.deepEqual(io.stdout.buffer, []);
    });

  });
});

describe('Daemon Agent', ()=> {
  let stopDaemon;
  afterEach(()=> {
    stopDaemon && stopDaemon();
    stopDaemon = null;
  });

  describe('encypted transport', ()=> {
    it('Decrypt data', (done)=> {
      const io = getIO();
      stopDaemon = agent.run({
        agent: true,
        silent: true,
        key: asset('Key40A0.cer'),
        cert: [
          asset('SELF_SIGNED_ENC_40A0.cer'),
        ],
      });

      agent.run({
        decrypt: true,
        connect: true,
        input: asset('enc_message.transport'),
      }, io, function() {
        assert.deepEqual(io.stderr.buffer, ['Encrypted']);
        assert.deepEqual(io.stdout.buffer, [Buffer.from('123')]);
        done();
      });
    });

    it('check signature and decrypt', (done)=> {
      stopDaemon = agent.run({
        agent: true,
        silent: true,
        key: [asset('Key6929.cer'), asset('PRIV1.cer')],
        cert: [asset('SELF_SIGNED_ENC_6929.cer'), asset('SELF_SIGNED1.cer')],
      });
      const io = getIO();

      agent.run({
        tax: true,
        connect: true,
        crypt: asset('SELF_SIGNED_ENC_40A0.cer'),
        input: io.asset('clear.txt', Buffer.from('This was encrypted')),
        output: io.asset('encrypted.p7s'),
      }, io, function () {
        stopDaemon();
        stopDaemon = agent.run({
          agent: true,
          silent: true,
          key: asset('Key40A0.cer'),
          cert: asset('SELF_SIGNED_ENC_40A0.cer'),
        });

        agent.run({
          decrypt: true,
          connect: true,
          input: io.asset('encrypted.p7s'),
        }, io, function () {

        assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA', 'Encrypted']);
        assert.deepEqual(io.stdout.buffer, [Buffer.from('This was encrypted')]);
        done();
      })
      });
    });

    it('check signature', (done)=> {
      stopDaemon = agent.run({
        agent: true,
        silent: true,
        key: asset('PRIV1.cer'),
        cert: asset('SELF_SIGNED1.cer'),
      });

      const io = getIO();
      agent.run({
        sign: true,
        connect: true,
        input: io.asset('clear.txt', Buffer.from('This is me')),
        output: io.asset('signed.p7s'),
      }, io, function () {
      agent.run({
          decrypt: true,
          connect: true,
          input: io.asset('signed.p7s'),
      }, io, function () {

      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
      done();

      });
      });

    });

  });
});

