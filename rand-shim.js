global.crypto = require('crypto');
if(global.crypto.getRandomValues === undefined) {
    global.crypto.getRandomValues = function(xb) {
        var i;
        var ret = global.crypto.rng(xb.length);
        if (!xb) {
            return ret;
        }
        for(i=0; i< xb.length; i++) {
            xb[i] = ret[i];
        }
        return xb;
    };
}
