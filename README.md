# Usage

## Sign and encrypt file with transport header

Ready to send to tax office:

    node index.js --sign --crypt  otrimano.cer \
                --key Key-6.dat:password \
                --cert cert.sign.der --cert cert.cryp.der \
                --input zvit.xml --output zvit.xml.sign.enc \
                --email ilya.muromec@gmail.com


## Sign file

If email is not specified in commandline, transport header would not be added.

    node index.js --sign \
                --key Key-6.dat:password \
                --cert cert.sign.der \
                --input zvit.xml --output zvit.xml.sign

## Load key from nonencrypted store

    node index.js --sign \
                --key Key-6.raw \
                --cert cert.sign.der \
                --input zvit.xml --output zvit.xml.sign

## Encrypt only

Notice, that both certificates are specified. This is implementation requirement, not really needed in code.

    node index.js --crypt  otrimano.cer \
                --key Key-6.dat:password \
                --cert cert.sign.der --cert cert.cryp.der \
                --input zvit.xml --output zvit.xml.sign.enc

## Agent mode

Signer can operate as out-of-process agent. One process would load key storage and listen to local socket,
while other would pass data to be signed to it.

Example:

    node index.js --agent \
                  --key Key-6.dat:password \
                  --cert cert.ipp.sign --cert cert.ipp.cryp &
    node index.js --connect \
                  --sign \
                  --input zvit.xml --output zvit.xml.sign
