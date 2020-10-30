const daemon = require('./lib/frame/daemon.js');
const client = require('./lib/frame/client.js');
const http = require('./lib/http');
const fs = require('fs');
const encoding = require("encoding");
const gost89 = require('gost89');
const jk = require('jkurwa');

const algos = gost89.compat.algos;
const Certificate = jk.models.Certificate;
const Priv = jk.models.Priv;
const Box = jk.Box;

const io = {
  stdout: process.stdout,
  readFileSync: fs.readFileSync,
  writeFileSync: fs.writeFileSync,
};

function error(...all) {
  if (io.stderr) {
    all.forEach((path)=> io.stderr.write(path));
  } else {
    console.error(...all);
  }
}

function output(filename, data, isWin) {
  if (typeof filename === 'string' && filename !== '-') {
    io.writeFileSync(filename, data);
  } else {
    io.stdout.write(
      isWin ? encoding.convert(data, 'utf-8', 'cp1251') : data
    );
  }
}

function dateStr(d) {
    d = d || new Date();
    return d.toISOString().replace(/[\-T:Z.]/g, '').slice(0, 14);
}

function key_param_parse (key) {
    let pw;
    if (key.indexOf(':') !== -1) {
        pw = key.substr(key.indexOf(':') + 1);
        key = key.substr(0, key.indexOf(':'));
    }
    return {
        path: key,
        pw: pw,
    };
}

async function get_local_box (key, cert) {
    const param = {algo: algos(), query: http.query};
    if (key) {
        key = key_param_parse(key);
        param.keys = param.keys || [{}];
        param.keys[0].privPath = key.path;
        param.keys[0].password = key.pw;
    }
    if (cert) {
        param.keys = param.keys || [{}];
        param.keys[0].certPath = cert;
    }

    return new Box(param);
}

async function do_sc(shouldSign, shouldCrypt, box, inputF, outputF, certRecF, edrpou, email, filename, tax, detached, role, tsp, encode_win, time) {
    let content = io.readFileSync(inputF);
    let cert_rcrypt;

    if (shouldCrypt) {
        let buf = fs.readFileSync(certRecF || shouldCrypt);
        cert_rcrypt = Certificate.from_asn1(buf).as_pem();
        shouldCrypt = true;
    }
    
    const ipn_ext = box.keys[0].cert.extension.ipn;
    const subject = box.keys[0].cert.subject;

    let headers;
    if (email && tax) {
        if (filename === undefined) {
            filename = inputF.replace(/\\/g, '/').split('/');
            filename = filename[filename.length - 1];
        }
        headers = {
            CERTYPE: "UA1",
            RCV_NAME: encoding.convert(subject.organizationName, 'cp1251'),
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
            headers.ENCODING = 'WIN';
            content = encoding.convert(content, 'cp1251');
        }
    }

    const pipe = [];
    if (shouldSign === true) {
        pipe.push({
          op: 'sign',
          tax: Boolean(tax),
          detached: Boolean(detached),
          role: role,
          tsp: tsp,
          time: time,
        });
    }
    if (shouldCrypt === true) {
        pipe.push({
            op: 'encrypt',
            forCert: cert_rcrypt,
            addCert: true,
            tax: Boolean(tax),
            role: role,
        });
        pipe.push({
          op: 'sign',
          tax: Boolean(tax),
          detached: Boolean(detached),
          role: role,
          tsp: tsp,
          time: time,
        });
    }
    const tb = await box.pipe(content, pipe, headers);
    output(outputF, tb);
    box.sock && box.sock.destroy();
}

async function do_parse(inputF, outputF, box, tsp) {
    let content, content2;
    if (typeof inputF === 'string') {
        content = io.readFileSync(inputF);
    } else {
        content = io.readFileSync(inputF[0]);
        content2 = io.readFileSync(inputF[1]);
    }

    const textinfo = await box.unwrap(content, content2, {tsp});
    const rpipe = (textinfo.pipe || []);

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
        if (tr.ENCODING === 'WIN') {
            isWin = true;
            Object.keys(tr).forEach(key=> {
              tr[key] = encoding.convert(tr[key], 'utf8', 'cp1251').toString();
            });
        }
        if (tr.SUBJECT) {
            error('Subject:', tr.SUBJECT);
        }
        if (tr.FILENAME) {
            error("Filename:", tr.FILENAME);
        }
        if (tr.EDRPOU) {
            error('Sent-By-EDRPOU:', tr.EDRPOU);
        }
        if (step.signed) {
            error('Signed-By:', x.subject.commonName || x.subject.organizationName);
            if (x.extension.ipn && x.extension.ipn.EDRPOU) {
                error('Signed-By-EDRPOU:', x.extension.ipn.EDRPOU);
            }
        }
        if (step.contentTime) {
            error('Content-Time-TSP:', step.contentTime / 1000);
        }
        if (step.tokenTime) {
            error('Signature-Time-TSP:', step.tokenTime / 1000);
        }
        if (step.signingTime) {
            error('Signature-Time:', step.signingTime/ 1000);
        }

        if (step.enc) {
            error("Encrypted");
        }
    });

    if (isErr === false) {
        output(outputF, textinfo.content, isWin);
    }
    if (box.sock) {
        box.sock.destroy();
    }
}

function unprotect(key, outputF) {
  key = key_param_parse(key);
  const buf = fs.readFileSync(key.path);
  const store = Priv.from_protected(buf, key.pw, algos());

  store.keys.forEach(function (key) {
    output(outputF, key.as_pem());
  });

  return true;
}


async function main(argv, setIo) {
  setIo && Object.assign(io, setIo);

  if (argv.unprotect) {
      if(!unprotect(argv.key, argv.output)) {
          process.exit(1);
      }
      return;
  }

  let box;
  if(argv.connect) {
      box = await new Promise(client.remoteBox);
  } else {
      box = await get_local_box(argv.key, argv.cert);
  }

  if (argv.sign || argv.crypt) {
      if (argv.crypt === true && !argv.recipient_cert) {
          return error('Please specify recipient certificate for encryption mode: --crypt filename.cert');
      }
      await do_sc(argv.sign, argv.crypt, box, argv.input, argv.output, argv.recipient_cert, argv.edrpou, argv.email, argv.filename, argv.tax, argv.detached, argv.role, argv.tsp, argv.encode_win, argv.time && Number(argv.time));
  }

  if (argv.decrypt) {
      await do_parse(argv.input, argv.output, box, argv.tsp);
  }


  if (argv.agent && !argv.connect) {
      return daemon.start({box, silent: argv.silent});
  }
}

module.exports = {main};
