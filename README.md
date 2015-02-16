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

## Unwrap

To unwrap and decrypt incoming messages, use `--decrypt` command-line switch. Notice that certificate is nod required here.

    node index.js --decrypt \
                --key fop_acsk.raw.der \
                --input incoming.encrypted \
                --output clear

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


Agent mode is available for encrypt and unwrap operations as well:

    # start agent as specified above
    node index.js --decrypt --connect --input encrypted.pkcs7 --output clear


## Key unwrapper

Normaly keys are stored inside encrypted file called Key-6.dat that requires password
to be decrypted every time it is being loaded.

However you can remove this protection from and store raw version of file.

    node index.js --unprotect --key Key-6.dat:password --output fop_acsk.raw.der
    node index.js --unprotect --key Key-6.dat:password > fop_acsk.raw.pem

Notice that without `--output` argument, private is outputed to standard output in PEM form.

## Notes

Starting from jkurwa version 0.4.20, agent can read documents created by "ME.DOC" software.
