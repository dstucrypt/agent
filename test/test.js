const assert = require("assert");
const fs = require("fs");

const agent = require("../agent");

function asset(name) {
  return `${__dirname}/../node_modules/jkurwa/test/data/${name}`;
}

class IOBuffer {
  constructor() {
    this.buffer = [];
  }

  write(piece) {
    this.buffer.push(piece);
  }
}

function getIO() {
  const assets = {};
  return {
    stdout: new IOBuffer(),
    stderr: new IOBuffer(),
    asset: function (filename, contents) {
      assets[`/dev/null/${filename}`] =
        contents || this.readAsset(filename) || Buffer.alloc(0);
      return `/dev/null/${filename}`;
    },
    readFileSync: function (filename) {
      return assets[filename] || fs.readFileSync(filename);
    },
    readAsset: function (filename) {
      return assets[`/dev/null/${filename}`];
    },
    writeFileSync: function (filename, contnets) {
      if (assets[filename]) {
        assets[filename] = contnets;
      } else {
        return fs.readFileSync(filename);
      }
    },
  };
}

beforeAll(() => {
  jest.spyOn(Date, "now").mockImplementation(() => 1600000000000);
});

describe("Local Agent", () => {
  describe("encypted p7s", () => {
    it("Decryption success", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.p7"),
          key: asset("Key40A0.cer"),
          cert: [
            asset("SELF_SIGNED_ENC_40A0.cer"),
            asset("SELF_SIGNED_ENC_6929.cer"),
          ],
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, ["Encrypted"]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
    });

    it("Decryption error when own cert is not supplied", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.p7"),
          key: asset("Key40A0.cer"),
          cert: [asset("SELF_SIGNED_ENC_6929.cer")],
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, [
        "Error occured during unwrap: ENOKEY",
      ]);
    });

    it("Decryption error when sender cert is not supplied", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.p7"),
          key: asset("Key40A0.cer"),
          cert: [asset("SELF_SIGNED_ENC_40A0.cer")],
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, [
        "Encrypted",
        "Error occured during unwrap: ENOCERT",
      ]);
    });
  });

  describe("encypted transport", () => {
    it("Decrypt data", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.transport"),
          key: asset("Key40A0.cer"),
          cert: [asset("SELF_SIGNED_ENC_40A0.cer")],
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
      assert.deepEqual(io.stderr.buffer, ["Encrypted"]);
    });

    it("Decrypt and write cleartext to file", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.transport"),
          output: io.asset("clear.txt"),
          key: asset("Key40A0.cer"),
          cert: [asset("SELF_SIGNED_ENC_40A0.cer")],
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, ["Encrypted"]);
      assert.deepEqual(io.readAsset("clear.txt"), Buffer.from("123"));
    });

    it("Decryption error when own cert is not supplied", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("enc_message.transport"),
          key: asset("Key40A0.cer"),
          cert: [asset("SELF_SIGNED_ENC_6929.cer")],
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, [
        "Error occured during unwrap: ENOKEY",
      ]);
    });
  });

  describe("signed p7s", () => {
    it("check signature", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("message.p7"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1540236305",
      ]);
    });

    it("check signature and complain about unathenticated signed", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("message.p7"),
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signer-Authentity:",
        "Not-Verified",
        "Signer-Authentity-Reason:",
        "No CA list supplied",
        "Signature-Time:",
        "1540236305",
      ]);
    });

    it("check signature and write cleatext to file", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("message.p7"),
          output: io.asset("clear.txt"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1540236305",
      ]);
      assert.deepEqual(io.readAsset("clear.txt"), Buffer.from("123"));
    });
  });

  describe("signed transport", () => {
    it("check signature", async () => {
      const io = getIO();
      await agent.main(
        {
          decrypt: true,
          input: asset("message.transport"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
      assert.deepEqual(io.stderr.buffer, [
        "Sent-By-EDRPOU:",
        "1234567891",
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1540236305",
      ]);
    });
  });

  describe("sign and unwrap", () => {
    it("check signature", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: io.asset("signed.p7s"),
          output: io.asset("signed.p7s"),
        },
        io
      );
      const signed = io.readAsset("signed.p7s");
      assert.equal(signed[0], 0x30);

      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
    });

    it("check signature with transport container", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          tax: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: io.asset("signed.p7s", true),
        },
        io
      );

      const signed = io.readAsset("signed.p7s");
      assert.deepEqual(signed.slice(0, 9).toString(), "UA1_SIGN\0");

      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
    });

    it("check signature with transport container including headers", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          tax: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: io.asset("signed.p7s"),
          email: "username@email.example.com",
          edrpou: "1234567891",
        },
        io
      );

      const signed = io.readAsset("signed.p7s");
      assert.deepEqual(signed.slice(0, 14).toString(), "TRANSPORTABLE\0");

      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Filename:",
        "clear.txt",
        "Sent-By-EDRPOU:",
        "1234567891",
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
    });

    it("write signature to stdout and decode cp1251 is specified in headers", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          encode_win: true,
          tax: true,
          email: "username@email.example.com",
          edrpou: "1234567891",
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me. ЖчССТБ!")),
          output: "-",
        },
        io
      );

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s", signed),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Filename:",
        "clear.txt",
        "Sent-By-EDRPOU:",
        "1234567891",
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me. ЖчССТБ!")]);
    });

    it("write signature to file without decoding content", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          encode_win: true,
          tax: true,
          email: "username@email.example.com",
          edrpou: "1234567891",
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me. ЖчССТБ!")),
          output: "-",
        },
        io
      );

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s", signed),
          output: io.asset("clear_out.txt"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Filename:",
        "clear.txt",
        "Sent-By-EDRPOU:",
        "1234567891",
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(
        io.readAsset("clear_out.txt"),
        Buffer.from("This is me. \xC6\xF7\xD1\xD1\xD2\xC1!", "binary")
      );
    });

    it("write signature to stdout", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: "-",
        },
        io
      );

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s", signed),
          ca_path: asset("CAList.cer"),
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
    });

    it("write detached signature to stdout and fail with ENODATA on parse", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          detached: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: "-",
        },
        io
      );

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      await agent.main(
        {
          decrypt: true,
          input: io.asset("signed.p7s", signed),
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Error occured during unwrap: ENODATA",
      ]);
      assert.deepEqual(io.stdout.buffer, []);
    });

    it("write detached signature to stdout and supply two files when parsing", async () => {
      const io = getIO();
      await agent.main(
        {
          sign: true,
          detached: true,
          key: asset("PRIV1.cer"),
          cert: asset("SELF_SIGNED1.cer"),
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: "-",
        },
        io
      );

      const signed = Buffer.concat(io.stdout.buffer);
      io.stdout.buffer = [];
      await agent.main(
        {
          decrypt: true,
          input: [
            io.asset("signed.p7s", signed),
            io.asset("clear.txt", Buffer.from("This is me")),
          ],
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
    });
  });

  describe("encrypt and decrypt", () => {
    it("check signature and decrypt", async () => {
      const io = getIO();
      await agent.main(
        {
          tax: true,
          crypt: asset("SELF_SIGNED_ENC_40A0.cer"),
          key: [asset("Key6929.cer"), asset("PRIV1.cer")],
          cert: [asset("SELF_SIGNED_ENC_6929.cer"), asset("SELF_SIGNED1.cer")],
          input: io.asset("clear.txt", Buffer.from("This was encrypted")),
          output: io.asset("encrypted.p7s"),
        },
        io
      );

      await agent.main(
        {
          decrypt: true,
          input: io.asset("encrypted.p7s"),
          key: asset("Key40A0.cer"),
          cert: asset("SELF_SIGNED_ENC_40A0.cer"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",

        "Encrypted",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This was encrypted")]);
    });

    it("encrypts when recipient is specified with --recipient_cert", async () => {
      const io = getIO();
      await agent.main(
        {
          tax: true,
          crypt: true,
          recipient_cert: asset("SELF_SIGNED_ENC_40A0.cer"),
          key: [asset("Key6929.cer"), asset("PRIV1.cer")],
          cert: [asset("SELF_SIGNED_ENC_6929.cer"), asset("SELF_SIGNED1.cer")],
          input: io.asset("clear.txt", Buffer.from("This was encrypted")),
          output: io.asset("encrypted.p7s"),
        },
        io
      );

      await agent.main(
        {
          decrypt: true,
          input: io.asset("encrypted.p7s"),
          key: asset("Key40A0.cer"),
          cert: asset("SELF_SIGNED_ENC_40A0.cer"),
          ca_path: asset("CAList.cer")
        },
        io
      );
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
        "Encrypted",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This was encrypted")]);
    });

    it("should fail when encryption recipient not specified", async () => {
      const io = getIO();
      await agent.main(
        {
          tax: true,
          crypt: true,
          key: [asset("Key6929.cer"), asset("PRIV1.cer")],
          cert: [asset("SELF_SIGNED_ENC_6929.cer"), asset("SELF_SIGNED1.cer")],
          input: io.asset("clear.txt", Buffer.from("This was encrypted")),
          output: io.asset("encrypted.p7s"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, [
        "Please specify recipient certificate for encryption mode: --crypt filename.cert",
      ]);
      assert.deepEqual(io.stdout.buffer, []);
    });
  });

  describe("Unprotect", () => {
    it("Decrypt password-protected key and write raw key", async () => {
      const io = getIO();
      await agent.main(
        {
          unprotect: true,
          key: asset("STORE_A040.pem:password"),
          output: io.asset("Key.pem"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, []);
      assert.deepEqual(io.stdout.buffer, []);
      assert.deepEqual(
        io.readAsset("Key.pem"),
        fs.readFileSync(asset("Key40A0.pem")).toString()
      );
    });

    it("Decrypt password-protected key and output raw key", async () => {
      const io = getIO();
      await agent.main(
        {
          unprotect: true,
          key: asset("STORE_A040.pem:password"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, []);
      assert.deepEqual(io.stdout.buffer, [
        fs.readFileSync(asset("Key40A0.pem")).toString(),
      ]);
    });

    it("output raw key in PEM", async () => {
      const io = getIO();
      await agent.main(
        {
          unprotect: true,
          key: asset("Key40A0.cer"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, []);
      assert.deepEqual(io.stdout.buffer, [
        fs.readFileSync(asset("Key40A0.pem")).toString(),
      ]);
    });
  });
});

describe("Daemon Agent", () => {
  let stopDaemon;
  afterEach(() => {
    stopDaemon && stopDaemon();
    stopDaemon = null;
  });

  describe("encypted transport", () => {
    it("Decrypt data", async () => {
      const io = getIO();
      stopDaemon = await agent.main({
        agent: true,
        silent: true,
        key: asset("Key40A0.cer"),
        cert: [asset("SELF_SIGNED_ENC_40A0.cer")],
      });

      await agent.main(
        {
          decrypt: true,
          connect: true,
          input: asset("enc_message.transport"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, ["Encrypted"]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
    });

    it("Decrypt data using password-protected key", async () => {
      const io = getIO();
      stopDaemon = await agent.main({
        agent: true,
        silent: true,
        key: asset("STORE_A040.pem:password"),
        cert: [asset("SELF_SIGNED_ENC_40A0.cer")],
      });

      await agent.main(
        {
          decrypt: true,
          connect: true,
          input: asset("enc_message.transport"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, ["Encrypted"]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("123")]);
    });

    it("check signature and decrypt", async () => {
      stopDaemon = await agent.main({
        agent: true,
        silent: true,
        key: [asset("Key6929.cer"), asset("PRIV1.cer")],
        cert: [asset("SELF_SIGNED_ENC_6929.cer"), asset("SELF_SIGNED1.cer")],
      });
      const io = getIO();

      await agent.main(
        {
          tax: true,
          connect: true,
          crypt: asset("SELF_SIGNED_ENC_40A0.cer"),
          input: io.asset("clear.txt", Buffer.from("This was encrypted")),
          output: io.asset("encrypted.p7s"),
        },
        io
      );
      stopDaemon();
      stopDaemon = await agent.main({
        agent: true,
        silent: true,
        key: asset("Key40A0.cer"),
        cert: asset("SELF_SIGNED_ENC_40A0.cer"),
        ca_path: asset("CAList.cer")
      });
      await agent.main(
        {
          decrypt: true,
          connect: true,
          input: io.asset("encrypted.p7s"),
        },
        io
      );

      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",

        "Encrypted",
      ]);
      assert.deepEqual(io.stdout.buffer, [Buffer.from("This was encrypted")]);
    });

    it("check signature", async () => {
      stopDaemon = await agent.main({
        agent: true,
        silent: true,
        key: asset("PRIV1.cer"),
        cert: asset("SELF_SIGNED1.cer"),
        ca_path: asset("CAList.cer")
      });

      const io = getIO();
      await agent.main(
        {
          sign: true,
          connect: true,
          input: io.asset("clear.txt", Buffer.from("This is me")),
          output: io.asset("signed.p7s"),
        },
        io
      );
      await agent.main(
        {
          decrypt: true,
          connect: true,
          input: io.asset("signed.p7s"),
        },
        io
      );

      assert.deepEqual(io.stdout.buffer, [Buffer.from("This is me")]);
      assert.deepEqual(io.stderr.buffer, [
        "Signed-By:",
        "Very Much CA",
        "Signature-Time:",
        "1600000000",
      ]);
    });
  });
});
