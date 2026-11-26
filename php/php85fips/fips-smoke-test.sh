#!/bin/sh
# Checks that OpenSSL and PHP run in FIPS mode with SHA-1 signing blocked.
set -eu

export OPENSSL_CONF=/usr/lib/ssl/openssl-fips.cnf

fail() {
    echo "FIPS smoke test failed: $1" >&2
    exit 1
}

openssl list -providers -verbose | grep -A3 '^  fips$' | grep -q 'status: active' \
    || fail "fips provider is not active"

if openssl list -providers | grep -q '^  default$'; then
    fail "default provider is loaded"
fi

php -r '
$key = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_RSA, "private_key_bits" => 2048]);
if ($key === false) {
    fwrite(STDERR, "could not create an RSA key\n");
    exit(1);
}
if (openssl_digest("x", "sha256") === false) {
    fwrite(STDERR, "sha256 digest does not work\n");
    exit(1);
}
if (@openssl_digest("x", "md5") !== false) {
    fwrite(STDERR, "md5 digest is allowed\n");
    exit(1);
}
if (!openssl_sign("x", $sig256, $key, OPENSSL_ALGO_SHA256)) {
    fwrite(STDERR, "sha256 signing does not work\n");
    exit(1);
}
if (@openssl_sign("x", $sig1, $key, OPENSSL_ALGO_SHA1)) {
    fwrite(STDERR, "sha1 signing is allowed\n");
    exit(1);
}
while (openssl_error_string() !== false);
' || fail "PHP openssl checks"

echo "FIPS smoke test passed"
