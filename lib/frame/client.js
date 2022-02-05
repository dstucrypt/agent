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

    var key = Buffer.alloc(32);
    var client = net.connect({path: bind}, function() {
        var frame = new Frame(key);
        frame.on('msg', client, opts.data);
        opts.connected(frame);
    });
    return client;
};

var RemoteBox = function (cb) {
    this.readyCB = cb;
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
        this.readyCB(this);
    }
    if (type === 'printstr' && contents.op === 'META') {
        data = this._data;
        delete this._data;
        this.unwrapCB(Object.assign({}, contents.meta, {content: data}));
    }
    if (type === 'printstr' && contents.op === 'RPIPE') {
        data = this._data;
        delete this._data;
        this.rpipeCB(data);
    }
    if (type === 'printstr' && contents.op === 'RCMP') {
        this.frame.send({op: 'INFO'});
    }
    if (type === 'printstr' && contents.op === 'ERROR') {
        if(contents.code === 'EPIPE') {
          this.rpipeCB({error: true});
        } else if (contents.code === 'EUNWRAP') {
          this.unwrapCB({error: true});
        } else if (contents.code === 'ECMP') {
          this.cmpCB({error: true});
        }
    }

    if (type === 'octstr') {
        this._data = contents;
    }

};

RemoteBox.prototype.pipe = function(content, pipe, opts, cb) {
    this.frame.send(content);
    this.frame.send({op: 'PIPE', pipe: pipe, opts: opts});

    return new Promise(resolve=> {
      this.rpipeCB = resolve;
    });
};

RemoteBox.prototype.unwrap = function(content, content2, opts) {
    this.frame.send(content);
    this.frame.send({op: 'UNWRAP', opts});
    return new Promise(resolve=> {
        this.unwrapCB = resolve;
    });
};

RemoteBox.prototype.findCertsCmp = function(urls) {
    return new Promise(resolve=> {
        this.frame.send({ op: 'CMP', urls });
        this.readyCB = resolve;
        this.cmpCB = resolve;
    });
}

var remoteBox = function(cb) {
    var box = new RemoteBox(cb);
};

module.exports.connect = connect;
module.exports.remoteBox = remoteBox;
