const http = require("http");
const https = require("https");
const url = require("url");

var query = function(method, toUrl, headers, payload, cb) {
    var parsed = url.parse(toUrl);
    var module = {'http:': http, 'https:': https}[parsed.protocol];
    var req = module.request({
        host:  parsed.host,
        path: parsed.path,
        headers: headers,
        method: method,
    }, function (res) {
        var chunks = [];
        res.on('data', function (chunk) {
            chunks.push(chunk);
        });
        res.on('end', function () {
            cb(Buffer.concat(chunks), res.statusCode);
        });
    });
    req.on('error', function(e) {
        cb(null, 599);
    });
    req.write(payload);
    req.end();
};

function query_promise(...args) {
  return new Promise((resolve)=> {
    query(...[...args, resolve]);
  });
}

module.exports = {query, query_promise};
