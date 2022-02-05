"use strict";
var fs = require("fs"),
  path = require("path"),
  net = require("net"),
  jk = require("jkurwa"),
  gost89 = require("gost89"),
  Certificate = jk.models.Certificate,
  http = require("../http"),
  Frame = require("./Frame");

var certinfo = function (keyinfo) {
  var x = keyinfo.cert;
  if (x) {
    return x.as_dict();
  }
};

var boxes = {};
var sharedBox = {
  hasCA: false,
  verifiedCache: {},
  cas: {},
  casRDN: {},
};

function newBox({ ca }) {
  const box = new jk.Box({ algo: gost89.compat.algos(), query: http.query });
  if (ca && !sharedBox.hasCA) {
    let buf = fs.readFileSync(ca);
    Object.assign(box, sharedBox);
    box.loadCAs(buf);
    sharedBox.hasCA = true;
  } else if (ca) {
    Object.assign(box, sharedBox);
  }
  return box;
}

function createBox(opts) {
  const bid = gost89.gosthash(`${Math.random()}/${Date.now()}`).toString("hex");
  const box = newBox(opts);
  boxes[bid] = { box, ctime: Date.now(), atime: Date.now() };
  return bid;
}

function get_box(bid) {
  const ret = boxes[bid];
  if (!ret) {
    return null;
  }
  ret.atime = Date.now();
  return ret.box;
}

function remove_box(bid) {
  delete boxes[bid];
}

function rsplit(input, sep) {
  const idx = input.lastIndexOf(sep);
  return [input.slice(0, idx), input.slice(idx + 1)];
}

const S_15_MIN = 15 * 60;

function cleanup(cutoff_s = S_15_MIN) {
  const last_viable = Date.now() - cutoff_s * 1000;
  let purged = 0;
  for (let bid in boxes) {
    let box = boxes[bid];
    if (box.atime < last_viable) {
      delete boxes[bid];
      purged += 1;
    }
  }
}

var start = function (opts) {
  var home = process.env.HOME;
  var bind = opts.bind || "";
  if (bind === true) {
    bind = "";
  }
  var log = opts.silent ? () => null : console.log;
  if (!bind && !home) {
    throw new Error("Nowhere to bind");
  }

  if (!bind && !opts.tcp) {
    bind = path.join(home, ".dstu-agent.sock");
  }

  var key = opts.key ? Buffer.from(opts.key, "hex") : Buffer.alloc(32);
  var server = net.createServer(function (conn) {
    conn.on("error", function (e) {
      if (e.code === "ECONNRESET") {
        return;
      }
    });
    var frame = new Frame(key);
    frame.on("msg", conn, function (contents, type) {
      var box = contents.bid ? get_box(contents && contents.bid) : opts.box;
      var data, info;
      if (!["octstr", "printstr"].includes(type)) {
        return conn.end();
      }

      if (type === "octstr") {
        this._data = contents;
      } else if (contents.op === "INIT") {
        var bid = createBox(opts);
        frame.send({ op: "CREATED", bid });
      } else if (contents.op === "EVICT") {
        remove_box(contents.bid);
        frame.send({ op: "GONE", bid: contents.bid });
      } else if (contents.op === "ADD_KEY" && box) {
        box.load({ password: contents.password, keyBuffers: [this._data] });
        delete this._data;
        frame.send({ op: "DONE", bid: contents.bid });
      } else if (contents.op === "ADD_CERT" && box) {
        box.load({ certBuffers: [this._data] });
        delete this._data;
        frame.send({ op: "DONE", bid: contents.bid });
      } else if (contents.op === "INFO" && box) {
        frame.send({ op: "CERTS", certs: box.keys.map(certinfo) });
        frame.send({ op: "READY" });
      } else if (contents.op === "PIPE" && box) {
        box.pipe(this._data, contents.pipe, contents.opts).then(
          (data) => {
            delete this._data;
            frame.send(data);
            frame.send({ op: "RPIPE" });
          },
          (e) => {
            console.error("epipe", e);
            frame.send({ op: "ERROR", code: "EPIPE" });
          }
        );
      } else if (contents.op === "UNWRAP" && box) {
        box.unwrap(this._data, null, contents.opts).then(
          (info) => {
            delete this._data;
            frame.send(info.content);
            delete info.content;
            frame.send({ op: "META", meta: info });
          },
          (e) => {
            console.error("eunwrap", e);
            frame.send({ op: "ERROR", code: "EUNWRAP" });
          }
        );
      } else if (contents.op === "UNPROTECT") {
        let box = newBox(opts);
        box.load({ password: contents.password, keyBuffers: [this._data] });
        delete this._data;
        const keys = Object.values(box.pubIdx)
          .filter((part) => part.priv)
          .map((part) => {
            const pub = part.priv.pub();
            return {
              keyid: pub.keyid(box.algo).toString("hex"),
              contents: part.priv.to_pem(),
            };
          });
        frame.send({ op: "CLEAR", keys });
      } else if (contents.op === 'CMP') {
        box.findCertsCmp(contents.urls).then((number)=> {
          frame.send({ op: 'RCMP', number });
        }, ()=> {
          frame.send({ op: 'ERROR', code: 'ECMP'});
        });
      } else if (!box) {
        frame.send({ op: "ERROR", code: "ENOENT", bid: contents.bid });
      } else {
        frame.send({ op: "ERROR", code: "EPROTO" });
        conn.end();
      }
    });
  });
  function stop() {
    opts.tcp || fs.unlinkSync(bind);
    log("stopped listeing", bind);
    process.removeListener("SIGINT", sigintHandler);
    server.close();
    server.unref();
    global.clearInterval(cleanup.intervalId);
  }
  function sigintHandler(code) {
    stop();
    process.exit(128 + code);
  }
  const [bindHost, bindPort] = rsplit(bind, ":");
  server.listen(
    opts.tcp
      ? {
          port: Number(bindPort) || null,
          host: bindHost || null,
        }
      : { path: bind }
  );
  log("agent running on", server.address());
  process.on("SIGINT", sigintHandler);

  cleanup.intervalId = global.setInterval(
    cleanup.bind(null, opts.keep_alive),
    5 * 1000
  );

  return stop;
};

module.exports.start = start;
