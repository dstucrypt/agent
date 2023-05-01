'use strict';
var fs = require('fs'),
    path = require('path'),
    net = require('net'),
    Frame = require('./Frame');

var connect = function (opts) {
    var bind = undefined ; 
    if (opts.opts.bind) {
        //client specified --bind <host:port> OR --bind <unix socket name or windows pipe name>
        //client should be explicit and use --tcp flag for TCP connection
        bind = opts.opts.bind;
    }
    
    var home = process.env.HOME; 

    if (!bind && !home) {
        throw new Error("Nowhere to bind");
    }

    var key = Buffer.alloc(32);

    var isLocal = false
    var host, port, path

    if (!bind) {
        //by default user HOME env is used as a path to IPC socket name
        bind = path.join(home, '.dstu-agent.sock');
    }
   
    if (!opts.opts.tcp) {
        //here --bind is a path to an IPC socket on Unix or pipe on Windows
        isLocal = true        
    } else {
        //client wants TCP
        [host, port] = rsplit(bind, ":");
    }
    const connOptions = isLocal ? { path: bind } : { host: host, port: Number(port) };
    
    var client = net.connect(connOptions, function() {
        var frame = new Frame(key);
        frame.on('msg', client, opts.data);
        opts.connected(frame);
    });

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

function remoteBox(opts) {
    return new Promise(resolve => new RemoteBox(resolve, opts));
};

function rsplit(input, sep) {
    const idx = input.lastIndexOf(sep);
    return [input.slice(0, idx), input.slice(idx + 1)];
  }
  
module.exports.connect = connect;
module.exports.remoteBox = remoteBox;
