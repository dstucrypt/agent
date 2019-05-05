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

    var client = net.connect({path: bind}, function() {
        var frame = new Frame();
        frame.on('msg', client, opts.data);
        opts.connected(frame);
    });
    return client;
};

var RemoteBox = function (cb) {
    this.readyCb = cb;
    this.sock = connect({
        connected: this.haveLink.bind(this),
        data: this.haveData.bind(this),
    });
};

RemoteBox.prototype.haveLink = function(frame) {
    frame.send({op: 'INFO'});
    this.frame = frame;
};

RemoteBox.prototype.haveData = function(contents, type) {
    var data;
    if (type === 'printstr' && contents.op === 'CERTS') {
        this.keys = contents.certs.map(function (el) {
            return {cert: el};
        });
    }
    if (type === 'printstr' && contents.op === 'READY') {
        this.readyCb(this);
    }
    if (type === 'printstr' && contents.op === 'META') {
        data = this._data;
        delete this._data;
        this.unwrapCB(contents.meta, data);
    }
    if (type === 'printstr' && contents.op === 'RPIPE') {
        data = this._data;
        delete this._data;
        this.rpipeCB(data);
    }

    if (type === 'octstr') {
        this._data = contents;
    }

};

RemoteBox.prototype.pipe = function(content, pipe, opts, cb) {
    this.rpipeCB = cb;
    this.frame.send(content);
    this.frame.send({op: 'PIPE', pipe: pipe, opts: opts});
};

RemoteBox.prototype.unwrap = function(content, content2, cb) {
    this.unwrapCB = cb;
    this.frame.send(content);
    this.frame.send({op: 'UNWRAP'});
};

var remoteBox = function(cb) {
    var box = new RemoteBox(cb);
};

module.exports.connect = connect;
module.exports.remoteBox = remoteBox;
