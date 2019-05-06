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
      if (!contents) return asset(filename);
      assets[`/dev/null/${filename}`] = contents;
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
        output: io.asset('clear.txt', Buffer.alloc(0)),
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
        output: io.asset('clear.txt', Buffer.alloc(0)),
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
      }, io);

      agent.run({
        decrypt: true,
        input: io.asset('signed.p7s'),
      }, io);
      assert.deepEqual(io.stdout.buffer, [Buffer.from('This is me')]);
      assert.deepEqual(io.stderr.buffer, ['Signed-By:', 'Very Much CA']);
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

