#!/bin/bash

echo "Validates if the /etc/ssl subdirectories are adequately"
echo "owned by 'ssl-cert' group"
echo
echo "No changes shall be done by this script."
echo "Passive verification only"
echo

# count how many users have `ssl-cert` group
group_ssl_cert_count="$(grep -c ssl-cert /etc/group)"

echo "Users with 'ssl-cert' group: $group_ssl_cert_count"
echo

if [ $group_ssl_cert_count -ge 2 ]; then
  echo "Ummmm, I haven't exactly mastered the support for multi-users yet."
  echo
elif [ $group_ssl_cert_count -eq 0 ]; then
  echo "INFO: Nobody is in 'ssl-cert' UNIX group"
  echo "      To add a user to the 'ssl-cert' supplemental group, execute:"
  echo
  echo "    usermod -a -G ssl-cert ${USER}"
  echo
  echo "After the above command is done, either logout/relogin or "
  echo "do a new 'ssh localhost' login to get the new "
  echo "'ssl-cert' supplemental group."
  echo
fi

function test_and_verify_subdirs()
{
  local this_dir="$1"
  local expected_user="$2"
  local expected_group="$3"
  local expected_mod="$4"
  COMPLAIN=0
  if [ -e "$this_dir" ]; then
    echo "Directory $this_dir is already created."
    # Checking if file ownership is good
    file_user="$(stat -c %U "$this_dir")"
    if [ "$file_user" != "$expected_user" ]; then
      echo "  Actual file user ID  : $file_user"
      echo "  Expected file user ID: $expected_user"
      COMPLAIN=1
    else
      echo "  Correctly set at '$file_user' user."
    fi
    file_group="$(stat -c %G "$this_dir")"
    if [ "$file_group" != "$expected_group" ]; then
      echo "  Actual file group ID  : $file_group"
      echo "  Expected file group ID: $expected_group"
      COMPLAIN=1
    else
      echo "  Correctly set at '$file_group' group."
    fi
    # Checking if file permission is good
    file_mod="$(stat -c %a "$this_dir")"
    if [ "$file_mod" != "$expected_mod" ]; then
      echo "  Actual file permission: $file_mod"
      echo "  Expected file permission: $expected_mod"
      COMPLAIN=1
    else
      echo "  Correctly set at '$file_mod' file permission."
    fi
  else
    echo "Missing $this_dir directory ..."
  fi
}

test_and_verify_subdirs "/etc/ssl/ca"  "${USER}" "ssl-cert" "750"
test_and_verify_subdirs "/etc/ssl/etc" "${USER}" "ssl-cert" "750"
test_and_verify_subdirs "/etc/ssl/private" "${USER}" "ssl-cert" "750"
test_and_verify_subdirs "/etc/ssl/crl" "${USER}" "ssl-cert" "750"
echo

echo "${BASH_SOURCE[0]}: Done."

