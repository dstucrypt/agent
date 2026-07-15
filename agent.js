const daemon = require("./lib/frame/daemon.js");
const client = require("./lib/frame/client.js");
const proxy = require("./lib/frame/proxy.js");
const http = require("./lib/http");
const fs = require("fs");
const path = require("path");
const encoding = require("encoding");
const gost89 = require("gost89");
const dstu7564 = require("dstu7564");
const jk = require("jkurwa");

const algos = gost89.compat.algos;
const Certificate = jk.models.Certificate;
const Priv = jk.models.Priv;
const Box = jk.Box;

function getHashByAlias(hashAlgo)  {
  return {
    gost: 'Gost34311',
    dstu: 'Dstu7564-256',
    kupyna: 'Dstu7564-256'
  }[hashAlgo] || 'Gost34311';
}

const io = {
  stdout: process.stdout,
  readFileSync: fs.readFileSync,
  writeFileSync: fs.writeFileSync,
};

function error(...all) {
  if (io.stderr) {
    all.forEach((path) => io.stderr.write(path));
  } else {
    console.error(...all);
  }
}

class ReadFileError extends Error {}

function readFile(filename) {
  return new Promise((resolve, reject) => {
    fs.readFile(filename, (err, data) => {
      if (err) {
        error("read file", err.toString());
        reject(new ReadFileError());
      } else {
        resolve(data);
      }
    });
  });
}

async function upload(filename, data, uploadUrl) {
  const headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
  const uploadData = JSON.stringify([{
    fname: filename,
    contentBase64: data.toString('base64'),
  }]);
  const ret = await http.query_promise('POST', uploadUrl, headers, uploadData);
  console.log(ret.toString());
}
async function output(filename, data, isWin, uploadUrl) {
  if (typeof filename === "string" && filename !== "-") {
    io.writeFileSync(filename, data);
  } else {
    io.stdout.write(isWin ? encoding.convert(data, "utf-8", "cp1251") : data);
  }
}

function dateStr(d) {
  d = d || new Date();
  return d
    .toISOString()
    .replace(/[\-T:Z.]/g, "")
    .slice(0, 14);
}

function startsWithDisk(pathName) {
  if (process.platform !== 'win32') {
    return false;
  }
  if (!path.isAbsolute(pathName)) {
    return false;
  }
  let start = pathName.slice(0, 1);
  return start !== '/' || start !== '\\';
}

function key_param_parse(key) {
  let pw;
  let separatorIndex = key.indexOf(":");
  // Special keys on windows:
  // if path is absolute, then first colon cal be
  // part of the disk drive
  if (startsWithDisk(key)) {
    separatorIndex = key.indexOf(":", separatorIndex + 1);
  }
  if (separatorIndex !== -1) {
    pw = key.substr(separatorIndex + 1);
    key = key.substr(0, separatorIndex);
  }
  return {
    path: key,
    pw: pw,
  };
}

function tsp_arg(value) {
  if (value === true) {
    return "content";
  }
  return value;
}

function listOf(value) {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value;
  }
  return [value];
}

async function get_local_box(key, cert, ca, defaultHash) {
  const gostAlgo = algos();
  const hashes = {
    Gost34311: function (data) {
      return gostAlgo.hash(data);
    },
    Dstu4145le: function (data) {
      return gostAlgo.hash(data);
    },
    'Dstu7564-256': function(data) {
      return dstu7564.computeHash(32, data);
    },
    'Dstu7564-384': function(data) {
      return dstu7564.computeHash(48, data);
    },
    'Dstu7564-512': function(data) {
      return dstu7564.computeHash(64, data);
    },
    Dstu4145leWithDstu7564: function(data) {
      return dstu7564.computeHash(32, data);
    },
  };
  hashes['Dstu7564-256'].algo = 'Dstu7564-256';
  hashes['Dstu7564-384'].algo = 'Dstu7564-384';
  hashes['Dstu7564-512'].algo = 'Dstu7564-512';

  const algo = Object.assign({}, gostAlgo, { hashes: hashes });
  const box = new Box({ algo: algo, query: http.query, defaultHash });
  const keyInfo = listOf(key).map(key_param_parse);
  for (let { path, pw } of keyInfo) {
    let buf = await readFile(path);
    box.load({ keyBuffers: [buf], password: pw });
  }
  for (let path of listOf(cert)) {
    let buf = await readFile(path);
    box.load({ certPem: buf });
  }
  if (ca) {
    let buf = await readFile(ca);
    box.loadCAs(buf);
  }

  return box;
}

async function do_sc(
  shouldSign,
  shouldCrypt,
  box,
  inputF,
  outputF,
  uploadUrl,
  certRecF,
  edrpou,
  email,
  filename,
  tax,
  detached,
  role,
  tsp,
  ocsp,
  includeChain,
  encode_win,
  time,
  hashAlgo
) {
  let content = await readFile(inputF);
  let cert_rcrypt;

  if (shouldCrypt) {
    let buf = await readFile(certRecF || shouldCrypt);
    cert_rcrypt = Certificate.from_asn1(buf).as_pem();
    shouldCrypt = true;
  }
  if (!box.keys[0].cert) {
    error('No certificate loaded for key 0, use --cert filename or --cert-fetch url');
    return;
  }

  const ipn_ext = box.keys[0].cert.extension.ipn;
  const subject = box.keys[0].cert.subject;

  let headers;
  if (email && tax) {
    if (filename === undefined) {
      filename = inputF.replace(/\\/g, "/").split("/");
      filename = filename[filename.length - 1];
    }
    headers = {
      CERTYPE: "UA1",
      RCV_NAME: encoding.convert(subject.organizationName, "cp1251"),
      PRG_TYPE: "TRANSPORT GATE",
      PRG_VER: "1.0.0",
      SND_DATE: dateStr(),
      FILENAME: filename || inputF,
      EDRPOU: edrpou || ipn_ext.EDRPOU,
    };
    if (email) {
      headers.RCV_EMAIL = email;
    }
    if (encode_win) {
      headers.ENCODING = "WIN";
      content = encoding.convert(content, "cp1251");
    }
  }

  const pipe = [];
  if (shouldSign === true) {
    pipe.push({
      op: "sign",
      tax: Boolean(tax),
      detached: Boolean(detached),
      role: role,
      tsp: tsp,
      ocsp: ocsp,
      includeChain: includeChain,
      time: time,
      hash: getHashByAlias(hashAlgo),
    });
  }
  if (shouldCrypt === true) {
    pipe.push({
      op: "encrypt",
      forCert: cert_rcrypt,
      addCert: true,
      tax: Boolean(tax),
      role: role,
    });
    pipe.push({
      op: "sign",
      tax: Boolean(tax),
      detached: Boolean(detached),
      role: role,
      tsp: tsp,
      ocsp: ocsp,
      includeChain: includeChain,
      time: time,
      hash: getHashByAlias(hashAlgo),
    });
  }
  const tb = await box.pipe(content, pipe, headers);
  if (tb.error) {
    error("Error occured inside the pipeline.");
    return false;
  }
  if(uploadUrl) {
    await upload(filename, tb, uploadUrl);
  } else {
    await output(outputF, tb, null, uploadUrl);
  }
  return true;
}

async function do_parse(inputF, outputF, box, tsp, ocsp) {
  let content, content2;
  if (typeof inputF === "string") {
    content = await readFile(inputF);
  } else if (inputF.length === 2) {
    content = await readFile(inputF[0]);
    content2 = await readFile(inputF[1]);
  }

  const textinfo = await box.unwrap(content, content2, { tsp, ocsp });
  const rpipe = textinfo.pipe || [];

  let isWin = false;
  let isErr = false;
  rpipe.forEach(function (step) {
    const x = step.cert;
    const tr = (step.transport ? step.headers : {}) || {};
    if (step.error) {
      isErr = true;
      error("Error occured during unwrap: " + step.error);
      return;
    }
    if (tr.ENCODING === "WIN") {
      isWin = true;
      Object.keys(tr).forEach((key) => {
        tr[key] = encoding.convert(tr[key], "utf8", "cp1251").toString();
      });
    }
    if (tr.SUBJECT) {
      error("Subject:", tr.SUBJECT);
    }
    if (tr.FILENAME) {
      error("Filename:", tr.FILENAME);
    }
    if (tr.EDRPOU) {
      error("Sent-By-EDRPOU:", tr.EDRPOU);
    }
    if (step.signed) {
      error("Signed-By:", x.subject.commonName || x.subject.organizationName);
      if (x.extension.ipn && x.extension.ipn.EDRPOU) {
        error("Signed-By-EDRPOU:", x.extension.ipn.EDRPOU);
      }
    }
    if (step.signed && !step.cert.verified) {
      error("Signer-Authentity:", "Not-Verified");
      error("Signer-Authentity-Reason:", "No CA list supplied");
    }
    if (step.ocsp) {
      for (let ocsp of step.ocsp) {
        error(
          "OCSP-Check:",
          ocsp.statusOk ? "OK" : ocsp.requestOk ? "Fail" : "Unknown",
          ocsp.isOcspStamp ? "Stamp" : "Online"
        );
        if (ocsp.hasOwnProperty("time")) {
          error("OCSP-Check-Time:", ocsp.time);
        }
      }
    }
    if (step.contentTime) {
      error("Content-Time-TSP:", step.contentTime / 1000);
    }
    if (step.tokenTime) {
      error("Signature-Time-TSP:", step.tokenTime / 1000);
    }
    if (step.signingTime) {
      error("Signature-Time:", step.signingTime / 1000);
    }

    if (step.enc) {
      error("Encrypted");
    }
  });

  if (isErr === false && outputF !== null) {
    await output(outputF, textinfo.content, isWin);
  }

  return true;
}

async function unprotect(key, outputF) {
  key = key_param_parse(key);
  const buf = fs.readFileSync(key.path);
  const store = Priv.from_protected(buf, key.pw, algos());

  for(let key of store.keys) {
    await output(outputF, key.as_pem());
  }

  return true;
}

async function main(argv, setIo) {
  let ret = false;
  setIo && Object.assign(io, setIo);

  jk.Curve.only_known = argv.only_known;

  if (argv.unprotect) {
    return await unprotect(argv.key, argv.output);
  }

  let box;
  if (argv.connect) {
    box = await client.remoteBox(argv); 
} else {
    box = await get_local_box(argv.key, argv.cert, argv.ca_path, getHashByAlias(argv.hash));
  }

  let certFetch = argv['cert-fetch'];
  if (certFetch) {
    let urls = [];
    if (typeof certFetch === 'string') {
      urls = [certFetch];
    } else if (Array.isArray(certFetch)) {
      urls = certFetch;
    }
    await box.findCertsCmp(urls);
  }

  if (argv.sign || argv.crypt) {
    if (argv.crypt === true && !argv.recipient_cert) {
      return error(
        "Please specify recipient certificate for encryption mode: --crypt filename.cert"
      );
    }
    ret = await do_sc(
      argv.sign,
      argv.crypt,
      box,
      argv.input,
      argv.output,
      argv.upload_url,
      argv.recipient_cert,
      argv.edrpou,
      argv.email,
      argv.filename,
      argv.tax,
      argv.detached,
      argv.role,
      tsp_arg(argv.tsp),
      argv.ocsp,
      argv.include_chain,
      argv.encode_win,
      argv.time && Number(argv.time),
      argv.hash
    );
  }

  if (argv.decrypt || argv.verify) {
    ret = await do_parse(
      argv.input || argv.decrypt || argv.verify,
      argv.verify ? null : argv.output,
      box,
      tsp_arg(argv.tsp),
      argv.ocsp
    );
  }

  if (argv.agent && !argv.connect) {
    return daemon.start({
      box,
      silent: argv.silent,
      bind: argv.bind,
      tcp: argv.tcp,
      ca: argv.ca_path,
      key: argv.connect_key,
      keep_alive: argv.keep_alive,
    });
  }

  if (argv.proxy) {
    return proxy.start({
      host: argv.proxy === true ? '::' : argv.proxy,
      silent: argv.silent,
      bind: argv.bind,
      key: argv.connect_key,
      ports: argv.ports,
    });
  }

  if (box && box.sock) {
    box.sock.destroy();
  }

  return ret;
}

module.exports = { main, ReadFileError };
