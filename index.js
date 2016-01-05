#!/usr/bin/env node
var argv = require('yargs')
    .usage('Sign, encrypt or decrypt UASIGN files')
    .argv;

var daemon = require('./lib/frame/daemon.js'),
    client = require('./lib/frame/client.js'),
    fs = require('fs'),
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

var get_box = function(key, cert) {
    var param = {algo: algos()};
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

var do_sc = function(shouldSign, shouldCrypt, box, inputF, outputF, certRecF, edrpou, email, filename) {
    var content = fs.readFileSync(inputF);

    var cert_rcrypt, buf;
    if (shouldCrypt) {
        buf = fs.readFileSync(certRecF || shouldCrypt);
        cert_rcrypt = Certificate.from_asn1(buf).as_pem();
        shouldCrypt = true;
    }
    
    var ipn_ext = box.keys[0].cert.extension.ipn;
    var subject = box.keys[0].cert.subject;

    var opts;
    if (email) {
        if (filename === undefined) {
            filename = inputF.replace(/\\/g, '/').split('/');
            filename = filename[filename.length - 1];
        }
        opts = {
            CERTYPE: "UA1",
            RCV_NAME: encoding.convert(subject.organizationName, 'cp1251'),
            PRG_TYPE: "TRANSPORT GATE",
            PRG_VER: "1.0.0",
            SND_DATE: date_str(),
            FILENAME: filename || inputF,
            EDRPOU: edrpou || ipn_ext.EDRPOU,
        };
        if (email) {
            opts.RCV_EMAIL = email;
        }
    }

    var pipe = [];
    if (shouldSign === true) {
        pipe.push('sign');
    }
    if (shouldCrypt === true) {
        pipe.push({
            op: 'encrypt',
            forCert: cert_rcrypt,
            addCert: true
        });
        if (shouldSign === true) {
            pipe.push('sign');
        }
    }
    var synctb = box.pipe(content, pipe, opts, function (tb) {
        fs.writeFileSync(outputF, tb);
        box.sock.unref();
    });
    if (Buffer.isBuffer(synctb)) {
        fs.writeFileSync(outputF, synctb);
    }
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
    var withBox = function(box) {
        do_sc(argv.sign, argv.crypt, box, argv.input, argv.output, argv.recipient_cert, argv.edrpou, argv.email, argv.filename);
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
