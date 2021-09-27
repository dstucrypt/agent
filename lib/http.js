const http = require("http");
const url = require("url");

var query = function(method, toUrl, headers, payload, cb) {
    var parsed = url.parse(toUrl);
    var req = http.request({
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

module.exports = {query};
