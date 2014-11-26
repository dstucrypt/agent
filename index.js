#!/usr/bin/env node
var argv = require('yargs')
    .usage('Sign, encrypt or decrypt UASIGN files')
    .argv;

var daemon = require('./lib/frame/daemon.js'),
    client = require('./lib/frame/client.js'),
    fs = require('fs'),
    encoding = require("encoding"),
    em_gost = require('em-gost'),
    jk = require('jkurwa'),
    Certificate = jk.models.Certificate,
    Box = jk.Box;

require('./rand-shim.js');

var keycoder = new jk.Keycoder();

var date_str = function(d) {
    d = d || new Date();
    return d.toISOString().replace(/[\-T:Z.]/g, '').slice(0, 14);
};

var algos = function () {
    return {
        kdf: em_gost.gost_kdf,
        keywrap: em_gost.gost_keywrap,
        keyunwrap: em_gost.gost_unwrap,
        encrypt: em_gost.gost_encrypt_cfb,
        decrypt: em_gost.gost_decrypt_cfb,
        hash: em_gost.compute_hash,
        storeload: em_gost.decode_data,
    };
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
    key = key_param_parse(key);
    return new Box({
        keys: [key],
        cert: cert,
        algo: algos()
    });

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
    var content = fs.readFileSync(inputF);

    var winMap = function (header, key) {
        header[key] = encoding.convert(header[key], 'utf8', 'cp1251').toString();
    };

    var unwraped = function(textinfo, content) {
        var rpipe = (textinfo.pipe || []);
        var isWin = false;
        rpipe.map(function (step) {
            var x = step.cert;
            var tr = (step.transport ? step.transport.header : {}) || {};
            if (tr.ENCODING === 'WIN') {
                isWin = true;
                Object.keys(tr).map(winMap.bind(null, tr));
            }
            if (tr.SUBJECT) {
                console.log('Subject:', tr.SUBJECT);
            }
            if (tr.FILENAME) {
                console.log("Filename:", tr.FILENAME);
            }
            if (tr.EDRPOU) {
                console.log('Sent-By-EDRPOU:', tr.EDRPOU);
            }
            if (step.signed) {
                console.log('Signed-By:', x.subject.commonName);
                console.log('Signed-By-EDRPOU:', x.extension.ipn.EDRPOU);
            }
            if (step.enc) {
                console.log("Encrypted");
            }
        });
        content = content || textinfo.content;
        if (typeof outputF === 'string') {
            fs.writeFileSync(outputF, content);
        } else {
            if (isWin) {
                content = encoding.convert(content, 'utf-8', 'cp1251');
            }
            console.log(content.toString());
        }
        if (box.sock) {
            box.sock.unref();
        }
    };

    var syncinf = box.unwrap(content, unwraped);
    if (typeof syncinf === 'object') {
        unwraped(syncinf);
    }
};

var unprotect = function(key, outputF) {
    key = key_param_parse(key);
    var buf = keycoder.maybe_pem(fs.readFileSync(key.path));
    var store = keycoder.parse(buf);
    var algo = algos();

    if (store.format === 'x509') {
        console.log("Not a key " + store.format);
        return;
    }
    if(store.format === 'IIT' || store.format === 'PBES2') {
        if (!key.pw) {
            console.log("specify password to decrypt");
            return;
        }

        buf = algo.storeload(store, key.pw);
        if (!buf) {
            console.log("Cannot decode store");
        }
        store = keycoder.parse(buf);
    }
    if (!outputF) {
        console.log('-----BEGIN PRIVATE KEY-----\n' +
                jk.b64_encode(buf, {line: 16, pad: true}) +
                '\n-----END PRIVATE KEY-----'
        );
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
        withBoxDec(get_box(argv.key, null));
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
