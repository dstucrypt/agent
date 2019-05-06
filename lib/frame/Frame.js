'use strict';

var Frame = function () {
    this.buffer = Buffer.alloc(0);
    this.pos = 0;
    this.ready = false;
    this.clen = 0;
    this.hlen = 0;
};

Frame.TYPES = {
    0x04: 'octstr',
    0x13: 'printstr',
};

Frame.prototype.append = function (data) {
    if (!Buffer.isBuffer(data)) {
        throw new Error("Pass buffer here");
    }
    this.buffer = Buffer.concat([this.buffer, data]);
    this.pos += data.length;

};

Frame.prototype.isReady = function () {
    this.ready = false;
    if (this.pos < 2) {
        return;
    }
    if (this.buffer[0] !== 0x04 && this.buffer[0] !== 0x13) {
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
        return Buffer.alloc(0);
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
    var type;
    var ct;
    while (true) {
        try {
            if (this.isReady() !== true) {
                break;
            }
        } catch (e) {
            console.log('broken frame', e);
            this.conn.destroy();
        }

        type = Frame.TYPES[this.buffer[0]];
        ct = this.slice();

        try {
            if (type === 'printstr') {
                ct = JSON.parse(ct);
            }
            this.msgCb(ct, type);
        } catch (e) {
            console.log('cant handle command', e);
            this.conn.destroy();
        }
    }
};

var encode_length = function (type, len) {
    var header;
    if (len < 0x80) {
        header = Buffer.alloc(2);
        header[0] = type;
        header[1] = len;
        return header;
    }

    if (len < 0x100) {
        header = Buffer.alloc(3);
        header[0] = type;
        header[1] = 0x81;
        header[2] = len;
        return header;
    }

    if (len < 0x10000) {
        header = Buffer.alloc(4);
        header[0] = type;
        header[1] = 0x82;
        header[2] = len >>> 8;
        header[3] = len & 0xFF;
        return header;
    }

    if (len < 0x1000000) {
        header = Buffer.alloc(5);
        header[0] = type;
        header[1] = 0x83;
        header[2] = len >>> 16;
        header[3] = (len >>> 8) & 0xFF;
        header[4] = len & 0xFF;
        return header;
    }


    throw new Error("Buf too long");
};

Frame.prototype.send = function(data) {
    let type, buffer;
    if (Buffer.isBuffer(data)) {
        type = 0x04;
        buffer = data;
    } else {
        buffer = Buffer.from(JSON.stringify(data), 'utf8');
        type = 0x13;
    }

    this.conn.write(encode_length(type, buffer.length));
    this.conn.write(buffer);
};

module.exports = Frame;
