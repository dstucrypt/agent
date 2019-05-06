var daemon = require('./lib/frame/daemon.js'),
    client = require('./lib/frame/client.js'),
    http = require('./lib/http'),
    fs = require('fs'),
    encoding = require("encoding"),
    gost89 = require('gost89'),
    jk = require('jkurwa'),
    algos = gost89.compat.algos,
    Certificate = jk.models.Certificate,
    Priv = jk.models.Priv,
    Box = jk.Box;

require('./rand-shim.js');

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

var date_str = function(d) {
    d = d || new Date();
    return d.toISOString().replace(/[\-T:Z.]/g, '').slice(0, 14);
};

var key_param_parse = function(key) {
    var pw;
    if (key.indexOf(':') !== -1) {
        pw = key.substr(key.indexOf(':') + 1);
        key = key.substr(0, key.indexOf(':'));
    }
    return {
        path: key,
        pw: pw,
    };
};

async function get_local_box (key, cert) {
    var param = {algo: algos(), query: http.query};
    if (key) {
        key = key_param_parse(key);
        param.keys = param.keys || [{}];
        param.keys[0].privPath = key.path;
        param.keys[0].password = key.pw;
    }
    if (cert) {
        param.keys[0].certPath = cert;
    }

    return new Box(param);
}

async function do_sc(shouldSign, shouldCrypt, box, inputF, outputF, certRecF, edrpou, email, filename, tax, detached, role, tsp, encode_win) {
    var content = io.readFileSync(inputF);

    var cert_rcrypt, buf;
    if (shouldCrypt) {
        buf = fs.readFileSync(certRecF || shouldCrypt);
        cert_rcrypt = Certificate.from_asn1(buf).as_pem();
        shouldCrypt = true;
    }
    
    var ipn_ext = box.keys[0].cert.extension.ipn;
    var subject = box.keys[0].cert.subject;

    var headers;
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
            SND_DATE: date_str(),
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

    var pipe = [];
    if (shouldSign === true) {
        pipe.push({
          op: 'sign',
          tax: Boolean(tax),
          detached: Boolean(detached),
          role: role,
          tsp: tsp,
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
        });
    }
    let tb = await box.pipe(content, pipe, headers);
    if (typeof outputF === 'string' && outputF !== '-') {
        io.writeFileSync(outputF, tb);
    } else {
        io.stdout.write(tb);
    }
    box.sock && box.sock.destroy();
}

async function do_parse(inputF, outputF, box) {
    let content, content2;
    if (typeof inputF === 'string') {
        content = io.readFileSync(inputF);
    } else {
        content = io.readFileSync(inputF[0]);
        content2 = io.readFileSync(inputF[1]);
    }

    const textinfo = await box.unwrap(content, content2);
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
        if (step.enc) {
            error("Encrypted");
        }
    });

    if (isErr === false) {
        let content = textinfo.content;
        if (typeof outputF === 'string' && outputF !== '-') {
            io.writeFileSync(outputF, content);
        } else {
            if (isWin) {
                content = encoding.convert(content, 'utf-8', 'cp1251');
            }
            io.stdout.write(content);
        }
    }
    if (box.sock) {
        box.sock.destroy();
    }
}

var unprotect = function(key, outputF) {
    key = key_param_parse(key);
    var buf = fs.readFileSync(key.path);
    var store = Priv.from_protected(buf, key.pw, algos());

    if (!outputF) {
        store.keys.map(function (key) {
            console.log(key.as_pem());
        });
        return true;

    }
    fs.writeFileSync(outputF, buf);
    return true;
};



async function main(argv, setIo) {
  setIo && Object.assign(io, setIo);

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
      await do_sc(argv.sign, argv.crypt, box, argv.input, argv.output, argv.recipient_cert, argv.edrpou, argv.email, argv.filename, argv.tax, argv.detached, argv.role, argv.tsp, argv.encode_win);
  }

  if (argv.decrypt) {
      await do_parse(argv.input, argv.output, box);
  }

  if (argv.unprotect) {
      if(!unprotect(argv.key, argv.output)) {
          process.exit(1);
      }
  }

  if (argv.agent && !argv.connect) {
      return daemon.start({box, silent: argv.silent});
  }
}

module.exports = {main};
