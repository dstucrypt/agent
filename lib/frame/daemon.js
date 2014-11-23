'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    Frame = require('./Frame');


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
        var i = 0;
        var frame = new Frame();
        frame.on('msg', conn, function (contents) {
            console.log('frame is ready', contents.toString(), contents);
            conn.write(new Buffer('3004', 'hex'));
            conn.write('yo!' + i);
            i ++ ;
        });
    });
    server.listen(bind);

};

module.exports.start = start;
