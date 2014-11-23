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
        frame.send('0123456789ABCDEF');
        frame.send('ZXYNMLKGIHGFEDCBA');
        frame.send('');
    });
    frame.on('msg', client, function (contents) {
        console.log('frame is ready', contents.toString(), contents);
    });
};

module.exports.connect = connect;
