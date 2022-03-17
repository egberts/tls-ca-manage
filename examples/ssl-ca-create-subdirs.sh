#!/bin/bash

GROUP_SSL_CERT='ssl-cert'

echo "Creates the /etc/ssl subdirectories as being "
echo "owned by the 'ssl-cert' group"
echo
THIS_USER="${THIS_USER:-$1}"

# count how many users have `ssl-cert` group
group_ssl_cert_count="$(grep -c "$GROUP_SSL_CERT" /etc/group)"

echo "Users with '${GROUP_SSL_CERT}' group: $group_ssl_cert_count"

if [ $group_ssl_cert_count -ge 2 ]; then
  echo "Ummmm, I haven't exactly mastered multi-users yet."
  echo "Aborted."
  echo
elif [ $group_ssl_cert_count -eq 1 ]; then
  echo "Using '$THIS_USER' as sole operator of '${GROUP_SSL_CERT}' group"
  echo
fi

function test_and_mkdir()
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
    echo "Creating $this_dir directory ..."
    mkdir "$this_dir"
    echo "Setting $this_dir directory to ${expected_user}:${expected_group} file ownership ..."
    chown "${expected_user}:${expected_group}" "$this_dir"
    echo "Setting $this_dir directory to $expected_mod file permission ..."
    chmod "$expected_mod" "$this_dir"
  fi
}

# there is no reason for general users to examine the SSL config files
test_and_mkdir "/etc/ssl/etc" "${THIS_USER}" "${GROUP_SSL_CERT}" "750"

# CA and CRL should be world read-able.
test_and_mkdir "/etc/ssl/ca"  "${THIS_USER}" "${GROUP_SSL_CERT}" "755"
test_and_mkdir "/etc/ssl/crl" "${THIS_USER}" "${GROUP_SSL_CERT}" "755"

# Private directory should be writable only by one-user (at the moment)
# Readable by other 'ssl-cert' group (but not by server applications).
test_and_mkdir "/etc/ssl/private" "${THIS_USER}" "${GROUP_SSL_CERT}" "750"
echo

echo "Done."

