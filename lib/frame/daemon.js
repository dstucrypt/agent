'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    jk = require('jkurwa'),
    Certificate = jk.models.Certificate,
    Frame = require('./Frame');

var certinfo = function (keyinfo) {
    var x = keyinfo.cert;
    if (x) {
        return x.as_dict();
    }
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
            var data, info;
            if (type === 'printstr' && contents.op === 'INFO') {
                frame.send({op: 'CERTS', certs: opts.box.keys.map(certinfo)});
                frame.send({op: 'READY'});
            }
            if (type === 'printstr' && contents.op === 'PIPE') {
                opts.box.pipe(this._data, contents.pipe, contents.opts, function (data) {
                    delete this._data;
                    frame.send(data);
                    frame.send({op: 'RPIPE'});
                });
            }
            if (type === 'printstr' && contents.op === 'UNWRAP') {
                info = opts.box.unwrap(this._data);
                delete this._data;
                frame.send(info.content);
                delete info.content;
                frame.send({op: 'META', meta: info});
            }
            if (type === 'octstr') {
                this._data = contents;
            }
        });
    });
    server.listen(bind);
    console.log('agent running on', bind);
    process.on('SIGINT', function(code) {
        fs.unlinkSync(bind);
        console.log('stopped listeing', bind);
        process.exit(128 + code);
    });
};

module.exports.start = start;
