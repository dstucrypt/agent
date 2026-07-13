#!/usr/bin/env node
/**
 * Download Ukraine's Trust Service Status List and extract all
 * X.509 certificates into a PKCS#7 CA bundle for --ca_path.
 *
 * Pure JavaScript — no shell, no openssl needed.
 *
 * Usage:  node tools/fetch-trust-list.js [url] [output.p7b]
 */

var https = require("https");
var fs = require("fs");
var jk = require("jkurwa");
var Message = jk.models.Message;
var Certificate = jk.models.Certificate;

var TL_URL = process.argv[2] || "https://czo.gov.ua/download/tl/TL-UA-DSTU.xml";
var OUTPUT = process.argv[3] || "trusted-cas.p7b";

console.error("Fetching TSL from " + TL_URL);

var body = [];

https.get(TL_URL, function(res) {
    if (res.statusCode !== 200) {
        console.error("HTTP " + res.statusCode);
        process.exit(1);
    }
    res.on("data", function(c) { body.push(c); });
    res.on("end", function() {
        var xml = Buffer.concat(body).toString("utf8");
        console.error("Downloaded " + xml.length + " bytes.");

        // Extract base64 certs from <X509Certificate> elements
        var re = /<X509Certificate>([^<]+)<\/X509Certificate>/g;
        var certsB64 = [];
        var match;
        while ((match = re.exec(xml)) !== null) {
            certsB64.push(match[1]);
        }
        console.error("Found " + certsB64.length + " certificates.");

        // Decode and parse
        var certs = [];
        certsB64.forEach(function(b64, i) {
            try {
                var der = Buffer.from(b64, "base64");
                var cert = Certificate.from_asn1(der);
                certs.push(cert.ob);
            } catch (e) {
                // skip unparseable — some certs may use ECDSA or unusual curves
            }
        });
        console.error("Loaded " + certs.length + " certificates.");

        // Build degenerate signedData — all certs, no signer, no content
        var msg = new Message();
        msg.wrap = {
            contentType: "signedData",
            content: {
                version: 1,
                digestAlgorithms: [],
                contentInfo: { contentType: "data" },
                certificate: certs,
                signerInfos: [],
            },
        };

        fs.writeFileSync(OUTPUT, msg.as_asn1());
        console.error("Wrote " + msg.as_asn1().length + " bytes to " + OUTPUT);
    });
    res.on("error", function(e) {
        console.error("Download error:", e.message);
        process.exit(1);
    });
}).on("error", function(e) {
    console.error("Connection error:", e.message);
    process.exit(1);
});
