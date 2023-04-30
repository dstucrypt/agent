'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    Frame = require('./Frame');

var connect = function (opts) {
    var bind = undefined ; //client may want sockets or tcp
    if (opts.opts.bind) {
        //wants tcp
        bind = opts.opts.bind;
    }
    var home = process.env.HOME; //client wants sockets

    if (!bind && !home) {
        throw new Error("Nowhere to bind");
    }

    if (!bind) {
        bind = path.join(home, '.dstu-agent.sock');
    }

    var key = Buffer.alloc(32);
    if (bind) {
        //client wants tcp
        const [bindHost, bindPort] = rsplit(bind, ":");

        var client = net.connect(Number(bindPort), bindHost, function() {
            var frame = new Frame(key);
            frame.on('msg', client, opts.data);
            opts.connected(frame);
        });
    } else {
        //client wants socket
        var client = net.connect({path: bind}, function() {
            var frame = new Frame(key);
            frame.on('msg', client, opts.data);
            opts.connected(frame);
        });
    }
    return client;
};

var RemoteBox = function (cb, opts) {
    this.readyCB = cb;
    this.sock = connect({
        connected: this.haveLink.bind(this),
        data: this.haveData.bind(this),
        opts: opts
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

    //cleint is sending second file with content being verified
    this.frame.send(content2);

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

var remoteBox = function(cb, opts) {
    var box = new RemoteBox(cb, opts);
};
function rsplit(input, sep) {
    const idx = input.lastIndexOf(sep);
    return [input.slice(0, idx), input.slice(idx + 1)];
  }
  
module.exports.connect = connect;
module.exports.remoteBox = remoteBox;
