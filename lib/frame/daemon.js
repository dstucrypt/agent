'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    Frame = require('./Frame');

var certinfo = function (keyinfo) {
    var x = keyinfo.cert;
    return {
        subject: x.subject,
        issuer: x.issuer,
        extension: x.extension,
        valid: x.valid,
    };
};

var start = function (opts) {
    var home = process.env.HOME;
    var bind = opts.bind;
    if (!bind && !home) {
        throw new Error("Nowhere to bind");
    }

    if (!bind) {
        bind = path.join(home, '.dstu-agent.sock');
    }

    var server = net.createServer(function(conn) {
        var frame = new Frame();
        frame.on('msg', conn, function (contents, type) {
            if (type === 'printstr' && contents.op === 'INFO') {
                frame.send({op: 'CERTS', certs: opts.box.keys.map(certinfo)});
                frame.send({op: 'READY'});
            }
            if (type === 'printstr' && contents.op === 'PIPE') {
                var data = opts.box.pipe(contents.data, contents.pipe, contents.opts);
                frame.send(data);
            }
        });
    });
    server.listen(bind);
    console.log('agent running on', bind);
};

module.exports.start = start;
