'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    Frame = require('./Frame');

var connect = function (opts) {
    var bind = opts.bind;
    var home = process.env.HOME;

    if (!bind && !home) {
        throw new Error("Nowhere to bind");
    }

    if (!bind) {
        bind = path.join(home, '.dstu-agent.sock');
    }

    var frame = new Frame();

    var client = net.connect({path: bind}, function () {
        client.write(new Buffer('3010', 'hex'));
        client.write(new Buffer('0123456789ABCDEF'));
        client.write(new Buffer('308111', 'hex'));
        client.write(new Buffer('ZXYNMLKGIHGFED'));
        client.write(new Buffer('4544473000', 'hex'));
    });
    frame.on('msg', client, function (contents) {
        console.log('frame is ready', contents.toString(), contents);
    });
};

module.exports.connect = connect;
