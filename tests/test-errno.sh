#!/bin/bash
# File: test-errno.sh
# Path: tests
# Title:  Test errno of all supplied commands
#
#  No files should have been created
#  Still needs a TEMP (/tmp/ssl), just in case
#
echo "Errno test"
echo
echo "You should be able to hold the ENTER key down and let it rip to its end."
echo "Demonstrates batch-mode"
echo


BASE_DIR="/tmp/ssl"
mkdir -p "$BASE_DIR"
TCAM_BIN="../tls-ca-manage.sh -b $BASE_DIR"

function assert_errno
{
  cmd="$1"
  expected_errno="$2"
  notes="$3"
  if [ $retsts -eq $expected_errno ]; then
    echo "expectedly passed"
  else
    echo "UNEXPECTEDLY FAILED: errno: $expected_errno"
    echo "Note: $notes"
    exit 1
  fi
}

function assert_errno_not
{
  retsts=$1
  expected_errno="$2"
  notes="$3"
  if [ $retsts -ne "$expected_errno" ]; then
    echo "expectedly failed"
  else
    echo "UNEXPECTEDLY PASSED: errno: $expected_errno"
    echo "Note: $notes"
    exit 1
  fi
}

$TCAM_BIN < /dev/null ; retsts=$? 
assert_errno_not $retsts 0 "empty arg"

$TCAM_BIN -h < /dev/null ; retsts=$? 
assert_errno_not $retsts 0 "option only"

$TCAM_BIN create < /dev/null ; retsts=$? 
assert_errno $retsts 1 "valid 1-arg create"

$TCAM_BIN verify < /dev/null ; retsts=$? 
assert_errno_not $retsts 0 "valid 1-arg verify"

$TCAM_BIN oppsie < /dev/null ; retsts=$? 
assert_errno $retsts 1 "invalid 1-arg"

$TCAM_BIN oppsie < /dev/null ; retsts=$? 
assert_errno $retsts 1 "invalid 1-arg"

echo
echo "If it got here, the whole thing passed."
