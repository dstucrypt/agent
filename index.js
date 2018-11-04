var argv = require('yargs')
    .usage('Sign, encrypt or decrypt UASIGN files')
    .option('tsp', {default: false})
    .option('tax', {default: true})
    .option('detached', {default: false})
    .option('role', {default: 'director'})
    .argv;

var daemon = require('./lib/frame/daemon.js'),
    client = require('./lib/frame/client.js'),
    fs = require('fs'),
    http = require("http"),
    url = require("url"),
    encoding = require("encoding"),
    gost89 = require('gost89'),
    jk = require('jkurwa'),
    algos = gost89.compat.algos,
    Certificate = jk.models.Certificate,
    Priv = jk.models.Priv,
    Box = jk.Box;

require('./rand-shim.js');

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

var query = function(method, toUrl, headers, payload, cb) {
    var parsed = url.parse(toUrl);
    var req = http.request({
        host:  parsed.host,
        path: parsed.path,
        headers: headers,
        method: method,
    }, function (res) {
        var chunks = [];
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            cb(Buffer.concat(chunks));
        });
    });
    req.on('error', function(e) {
        cb(null);
    });
    req.write(payload);
    req.end();
};

var get_box = function(key, cert) {
    var param = {algo: algos(), query: query};
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
};

var do_sc = function(shouldSign, shouldCrypt, box, inputF, outputF, certRecF, edrpou, email, filename, tax, detached, role, tsp) {
    var content = fs.readFileSync(inputF);

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
    synctb = box.pipe(content, pipe, headers, function (tb) {
        fs.writeFileSync(outputF, tb);
        box.sock && box.sock.unref();
    });
};

var do_parse = function(inputF, outputF, box) {
    var content, content2;
    if (typeof inputF === 'string') {
        content = fs.readFileSync(inputF);
    } else {
        content = fs.readFileSync(inputF[0]);
        content2 = fs.readFileSync(inputF[1]);
    }

    var winMap = function (header, key) {
        header[key] = encoding.convert(header[key], 'utf8', 'cp1251').toString();
    };

    var unwraped = function(textinfo, content) {
        var rpipe = (textinfo.pipe || []);
        var isWin = false;
        var isErr = false;
        rpipe.map(function (step) {
            var x = step.cert;
            var tr = (step.transport ? step.headers : {}) || {};
            if (step.error) {
                isErr = true;
                console.error("Error occured during unwrap: " + step.error);
                return;
            }
            if (tr.ENCODING === 'WIN') {
                isWin = true;
                Object.keys(tr).map(winMap.bind(null, tr));
            }
            if (tr.SUBJECT) {
                console.warn('Subject:', tr.SUBJECT);
            }
            if (tr.FILENAME) {
                console.warn("Filename:", tr.FILENAME);
            }
            if (tr.EDRPOU) {
                console.warn('Sent-By-EDRPOU:', tr.EDRPOU);
            }
            if (step.signed) {
                console.warn('Signed-By:', x.subject.commonName);
                if (x.extension.ipn && x.extension.ipn.EDRPOU) {
                    console.warn('Signed-By-EDRPOU:', x.extension.ipn.EDRPOU);
                }
            }
            if (step.enc) {
                console.warn("Encrypted");
            }
        });
        if (isErr === false) {
            content = content || textinfo.content;
            if (typeof outputF === 'string') {
                fs.writeFileSync(outputF, content);
            } else {
                if (isWin) {
                    content = encoding.convert(content, 'utf-8', 'cp1251');
                }
                process.stdout.write(content);
            }
        }
        if (box.sock) {
            box.sock.unref();
        }
    };

    var syncinf = box.unwrap(content, content2, unwraped);
    if (typeof syncinf === 'object') {
        unwraped(syncinf);
    }
};

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

if (argv.sign || argv.crypt) {
    if (argv.crypt === true && !argv.recipient_cert) {
        throw new Error('Please specify recipient certificate for encryption mode: --crypt filename.cert');
    }
    var withBox = function(box) {
        do_sc(argv.sign, argv.crypt, box, argv.input, argv.output, argv.recipient_cert, argv.edrpou, argv.email, argv.filename, argv.tax, argv.detached, argv.role, argv.tsp);
    };
    if(argv.connect) {
        client.remoteBox(withBox);
    } else {
        withBox(get_box(argv.key, argv.cert));
    }
}

if (argv.decrypt) {
    var withBoxDec = function(box) {
        do_parse(argv.input, argv.output, box);
    };

    if(argv.connect) {
        client.remoteBox(withBoxDec);
    } else {
        withBoxDec(get_box(argv.key, argv.cert));
    }
}

if (argv.agent) {
    daemon.start({box: get_box(argv.key, argv.cert)});
}

if (argv.unprotect) {
    if(!unprotect(argv.key, argv.output)) {
        process.exit(1);
    }
}
