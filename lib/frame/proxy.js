'use strict';
var net = require('net');
var Frame = require('./Frame');


function cleanup(cutoff_ms) {
}

function rsplit(input, sep) {
    const idx = input.lastIndexOf(sep);
    return [input.slice(0, idx), input.slice(idx + 1)];
}

function cycle(idx, limit) {
  idx++;
  return idx < limit ? idx : 0;
}

var backs = {
  current: 0,
  list: [],
  by_bid: {}
};

var nop = ()=> null;

function connect() {
  backs.current = cycle(backs.current, backs.list.length);
  const {port, key}  = backs.list[backs.current];
  const socket = new net.Socket();
  const frame = new Frame(key);
  return new Promise((resolve, reject)=> {
    socket.connect(port, '::', function connected() {
      const back = {
        port,
        onmsg: nop,
        onclose: nop,
        lo: socket.address(),
        frame,
      };
      frame.on('msg', socket, (...args)=> back.onmsg(...args));
      socket.on('close', ()=> back.onclose());
      resolve(back);
    });
    socket.on('error', function(error) {
      reject(error);
    });
  });
}

async function get_back(bid, retry=1) {
  let ret;
  if(bid) {
    ret = backs.by_bid[bid];
  }
  while(!ret && retry-- > 0) {
    try {
      ret = await connect();
    } catch(e) {
      ret = null;
    }
  }
  return ret;
}

var start = function (opts) {
    var log = opts.silent ? (()=> null) : console.log;
    var bind = opts.bind;

    if (!bind) {
        throw new Error("Nowhere to bind");
    }

    var key = opts.key ? Buffer.from(opts.key, 'hex') : Buffer.alloc(32);
    var [lport, hport] = opts.ports.split(':').map(Number);
    var port = lport;
    while(port <= hport) {
      backs.list.push({port, key});
      port++;
    }

    var server = net.createServer(function(conn) {
        let data;
        let back;
        conn.on('error', function(e) {
            if(e.code === 'ECONNRESET') {
                return;
            }
        });
        conn.on('close', async function () {
          back && back.frame.conn.end();
        });
        var frame = new Frame(key);
        frame.on('msg', conn, async function (contents, type) {
          if(type === 'octstr') {
            data = contents;
            return;
          }
          let old = back;
          if(!back || contents.bid) {
            back = await get_back(contents.bid, 5);
          }
          if(!back) {
            frame.send({op: 'ERROR', code: 'EBUSY'});
            return conn.end();    
          }
          if(old && back !== old) {
            old.frame.conn.end();
          }
          back.onclose = function() {
            frame.send({op: 'ERROR', code: 'EBUSY'});
            return conn.end();    
          }

          back.onmsg = function proxy(_ct, _type) {
            if(_type === 'printstr' && _ct.op === 'CREATED') {
              backs.by_bid[_ct.bid] = back;
            }
            if(_type === 'printstr' && _ct.op === 'GONE') {
              delete backs.by_bid[_ct.bid];
            }
            if(_type === 'printstr' && _ct.op === 'ERROR' && _ct.code === 'ENOENT') {
              delete backs.by_bid[_ct.bid];
            }
            frame.send(_ct);
          }
          if(data) {
            back.frame.send(data);
            data = null;
          }
          back.frame.send(contents);
        });
    });
    function stop() {
        log('stopped listeing', bind);
        process.removeListener('SIGINT', sigintHandler);
        server.close();
        server.unref();
    }
    function sigintHandler(code) {
        stop();
        process.exit(128 + code);
    }
    const [bindHost, bindPort] = rsplit(bind, ':');
    server.listen({
      port: Number(bindPort) || null,
      host: bindHost || null,
    });
    log('agent proxy running on', server.address());
    process.on('SIGINT', sigintHandler);

    global.setInterval(cleanup.bind(null, 15 * 1000), 5 * 1000);

    return stop;
};

module.exports.start = start;
