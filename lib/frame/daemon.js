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
    var log = opts.silent ? (()=> null) : console.log;
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
                opts.box.pipe(this._data, contents.pipe, contents.opts).then(
                    data=> {
                      delete this._data;
                      frame.send(data);
                      frame.send({op: 'RPIPE'});
                    },
                    e=> {
                      frame.send({op: 'ERROR', code: 'EPIPE'});
                    }
                );
            }
            if (type === 'printstr' && contents.op === 'UNWRAP') {
                opts.box.unwrap(this._data, null, contents.opts).then(
                    info=> {
                        delete this._data;
                        frame.send(info.content);
                        delete info.content;
                        frame.send({op: 'META', meta: info});
                    },
                    e=> {
                        frame.send({op: 'ERROR', code: 'EUNWRAP'});
                     }
                );
            }
            if (type === 'octstr') {
                this._data = contents;
            }
        });
    });
    function stop() {
        fs.unlinkSync(bind);
        log('stopped listeing', bind);
        process.removeListener('SIGINT', sigintHandler);
        server.close();
        server.unref();
    }
    function sigintHandler(code) {
        stop();
        process.exit(128 + code);
    }
    server.listen(bind);
    log('agent running on', bind);
    process.on('SIGINT', sigintHandler);
    return stop;
};

module.exports.start = start;
