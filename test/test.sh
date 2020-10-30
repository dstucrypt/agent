#!/bin/bash

set -e

AGENT="node --trace-deprecation $(pwd)/index.js"
DATA=$(pwd)/node_modules/jkurwa/test/data
FILTER="$1"

decrypt () {
  $AGENT --decrypt $@
}

unwrap () {
  $AGENT --decrypt $@
}

sign () {
  $AGENT --sign --time 1641111111 $@
}

encrypt () {
  $AGENT --crypt $@ --time 1642222222
}

unprotect () {
  $AGENT --unprotect $@
}

start_daemon() {
  cd "$DATA"
  [ -S "$HOME/.dstu-agent.sock" ] && return 1
  $AGENT --agent $@ 1> /dev/null & DAEMON=$! ; disown
  cd - > /dev/null

  while [ ! -S "$HOME/.dstu-agent.sock" ] ; do
    sleep 0.1
  done
}

stop_daemon() {
  if [ "$DAEMON" != "" ]
  then
    kill -15 $DAEMON
    rm -f "$HOME/.dstu-agent.sock"
    DAEMON=""
  fi
}

assert () {
  stop_daemon
  rm -f "$TMPFILE"
  echo FAIL. $@
  exit 1
}

testcase () {
  TEST="$1"; shift
  EXPECT_OUT="$1"; shift
  EXPECT_ERR="$1"; shift

  [ "$FILTER" != "" ] && [ "${TEST/#${FILTER}/}" == "$TEST" ] && return

  if diff <($@ 2>&1 1>/dev/null) $EXPECT_ERR ; then
    true
  else
    assert $TEST
  fi

  if diff <($@ 2>/dev/null) "$EXPECT_OUT"; then
    true
  else
    assert $TEST
  fi

  echo PASS. $TEST
}

cd "$DATA"

testcase \
  "Decrypt p7s message" \
  <(echo -n 123) \
  <(echo Encrypted) \
  "decrypt --input enc_message.p7 --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer --cert SELF_SIGNED_ENC_6929.cer"

testcase \
  "Decryption error when own cert is not supplied" \
  <(true) \
  <(echo Error occured during unwrap: ENOKEY) \
  "decrypt --input enc_message.p7 --key Key40A0.cer --cert SELF_SIGNED_ENC_6929.cer"

testcase \
  "Decryption error when sender cert is not supplied" \
  <(true) \
<(cat <<EOF
Encrypted
Error occured during unwrap: ENOCERT
EOF
) \
  "decrypt --input enc_message.p7 --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer"

testcase \
  "Decrypt transport message without sender ceritifcate" \
  <(echo -n 123) \
  <(echo Encrypted) \
  "decrypt --input enc_message.transport --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer"

testcase \
  "Decryption error when own cert is not supplied" \
  <(true) \
  <(echo Error occured during unwrap: ENOKEY) \
  "decrypt --input enc_message.transport --key Key40A0.cer"

testcase \
  "Unwrap signed message" \
  <(echo -n 123) \
  <(cat <<EOF
Signed-By: Very Much CA
Signature-Time: 1540236305
EOF
) \
  "unwrap --input message.p7"

testcase \
  "Unwrap signed transport message" \
  <(echo -n 123) \
  <(cat <<EOF
Sent-By-EDRPOU: 1234567891
Signed-By: Very Much CA
Signature-Time: 1540236305
EOF
) \
  "unwrap --input message.transport"


TMPFILE=$(mktemp)
sign \
        --no-role \
        --key PRIV1.cer \
        --cert SELF_SIGNED1.cer \
        --input <(echo -n This is me) --output $TMPFILE

testcase \
  "Sign message and unwrap" \
  <(echo -n This is me) \
  <(cat <<EOF
Signed-By: Very Much CA
Signature-Time: 1641111111
EOF
) \
  "unwrap --input $TMPFILE"

rm $TMPFILE

TMPFILE=$(mktemp)
encrypt \
        SELF_SIGNED_ENC_40A0.cer \
        --no-role \
        --key Key6929.cer \
        --cert SELF_SIGNED_ENC_6929.cer \
        --key PRIV1.cer \
        --cert SELF_SIGNED1.cer \
        --input <(echo -n This was encrypted) --output $TMPFILE

testcase \
  "Encrypt message and decrypt" \
  <(echo -n This was encrypted) \
  <(cat <<EOF
Signed-By: Very Much CA
Signature-Time: 1642222222
Encrypted
EOF
) \
  "unwrap --input $TMPFILE --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer"

rm $TMPFILE

start_daemon --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer

testcase \
  "Daemon decrypt transport message" \
  <(echo -n 123) \
  <(echo Encrypted) \
  "decrypt --connect --input enc_message.transport"

testcase \
  "Daemon decrypt message error when sender cert not present" \
  <(true) \
  <(cat <<EOF
Encrypted
Error occured during unwrap: ENOCERT
EOF
) \
  "decrypt --connect --input enc_message.p7"

stop_daemon

start_daemon --key Key40A0.cer --cert SELF_SIGNED_ENC_40A0.cer --cert SELF_SIGNED_ENC_6929.cer

testcase \
  "Daemon decrypt message" \
  <(echo -n 123) \
  <(echo Encrypted) \
  "decrypt --connect --input enc_message.p7"

stop_daemon

start_daemon --key STORE_A040.pem:password --cert SELF_SIGNED_ENC_40A0.cer --cert SELF_SIGNED_ENC_6929.cer

testcase \
  "Daemon decrypt message using password-protected key" \
  <(echo -n 123) \
  <(echo Encrypted) \
  "decrypt --connect --input enc_message.p7"

stop_daemon

testcase \
  "Unpack password-protected store" \
  <(cat Key40A0.pem) \
  <(true) \
  "unprotect --key STORE_A040.pem:password"
