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
  return {
    stdout: new IOBuffer(),
    stderr: new IOBuffer(),
  };
}

describe('Agent', ()=> {
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
    }, io);
    assert.deepEqual(io.stderr.buffer, ['Error occured during unwrap: ENOKEY']);
  });
});
