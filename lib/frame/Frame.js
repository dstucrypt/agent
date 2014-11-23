'use strict';

var Frame = function () {
    this.buffer = new Buffer(10);
    this.pos = 0;
    this.ready = false;
    this.clen = 0;
    this.hlen = 0;
};

Frame.prototype.append = function (data) {
    var wlen;
    if (!Buffer.isBuffer(data)) {
        throw new Error("Pass buffer here");
    }

    wlen = data.copy(this.buffer, this.pos);
    if (wlen === data.length) {
        this.pos += wlen;
        return;
    }
    var nb = new Buffer(Math.max(this.buffer.length * 2, data.length * 2));
    this.buffer.copy(nb);
    this.buffer = nb;
    wlen = data.copy(this.buffer, this.pos);

    if (wlen !== data.length) {
        throw new Error("Failed to grow buffer");
    }
    this.pos += wlen;

};

Frame.prototype.isReady = function () {
    this.ready = false;
    if (this.pos < 2) {
        return;
    }
    if (this.buffer[0] !== 0x30) {
        throw new Error("Incorrect frame");
    }

    var len = this.buffer[1],
        lenOcts = 0,
        off;
    if (len & 0x80) {
        lenOcts = len ^ 0x80;
        len = 0;
        off = 2;
    }
    if (this.pos < (2 + lenOcts)) {
        return;
    }

    while (off < (lenOcts + 2)) {
        len = len << 8;
        len |= this.buffer[off];
        off ++;
    }

    if (this.pos < (len + lenOcts + 2)) {
        this.wait = (len + lenOcts + 2) - this.pos;
        return false;
    }

    this.clen = len;
    this.hlen = 2 + lenOcts;
    this.ready = true;
    return true;
};

Frame.prototype.slice = function () {
    if (!this.ready) {
        return new Buffer(0);
    }

    var contents = this.buffer.slice(this.hlen, this.clen + this.hlen);
    if (contents.length !== this.clen) {
        throw new Error("Internal framing error");
    }
    this.buffer = this.buffer.slice(this.clen + this.hlen);
    this.ready = false;
    this.pos -= this.clen + this.hlen;

    return contents;
};

Frame.prototype.on = function (evt, conn, cb) {
    if (evt !== 'msg') {
        return;
    }
    if (this.msgCb !== undefined) {
        throw new Error("Already bound");
    }

    conn.on('data', this.rawIn.bind(this));
    this.msgCb = cb;
    this.conn = conn;
};

Frame.prototype.rawIn = function (data) {
    this.append(data);
    while (true) {
        try {
            if (this.isReady() !== true) {
                break;
            }
        } catch (e) {
            console.log('broken frame');
            this.conn.destroy();
        }

        this.msgCb(this.slice());
    }
};

module.exports = Frame;
