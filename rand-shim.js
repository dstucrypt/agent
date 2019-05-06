global.crypto = require('crypto');
if(global.crypto.getRandomValues === undefined) {
    global.crypto.getRandomValues = function(xb) {
        const ret = global.crypto.rng(xb.length);
        for(let i=0; i< xb.length; i++) {
            xb[i] = ret[i];
        }
        return ret;
    };
}
