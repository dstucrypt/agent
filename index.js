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
        keys: [{
                privPath: key.path,
                certPath: cert,
                password: key.pw,
        }],
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

var do_parse = function(inputF, outputF, key) {
    var content = fs.readFileSync(inputF);
    var box = get_box(key, null);

    var textinfo = box.unwrap(content);
    if (typeof outputF === 'string') {
        fs.writeFileSync(outputF, textinfo.content);
    } else {
        console.log(textinfo.content.toString());
    }
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
    do_parse(argv.input, argv.output, argv.key);
}

if (argv.agent) {
    daemon.start({box: get_box(argv.key, argv.cert)});
}
