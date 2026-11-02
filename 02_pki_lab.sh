#!/usr/bin/env bash
# Lab 2 - PKI modernization: classical vs ML-DSA vs SLH-DSA-rooted hierarchies
#
# Needs OpenSSL 3.5 or newer (native ML-DSA / SLH-DSA).
#   OPENSSL=/path/to/openssl ./02_pki_lab.sh
#
# Builds four 3-tier hierarchies (root -> intermediate -> leaf):
#   classical : ECDSA P-256 everywhere
#   pq        : ML-DSA-87 root, ML-DSA-65 intermediate and leaf
#   slhroot   : SLH-DSA-SHA2-128s root (hash-based, most conservative),
#               ML-DSA-65 intermediate and leaf   <- a realistic migration design
#   slhfull   : SLH-DSA-SHA2-128s everywhere (shows how large it gets)
# Then: verifies each chain, prints size tables, issues and checks a CRL.
set -euo pipefail

OPENSSL=${OPENSSL:-openssl}
OUT=${OUT:-pki}
rm -rf "$OUT"
mkdir -p "$OUT"

echo "Using: $($OPENSSL version)"
for alg in ML-DSA-65 SLH-DSA-SHA2-128s; do
  if ! $OPENSSL list -signature-algorithms | grep -qi "${alg//-/}\|$alg"; then
    echo "ERROR: this OpenSSL does not list $alg. Need OpenSSL >= 3.5." >&2
    exit 1
  fi
done

genkey() {  # genkey <alg> <outfile>
  case "$1" in
    EC-P256) $OPENSSL genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$2" ;;
    *)       $OPENSSL genpkey -algorithm "$1" -out "$2" ;;
  esac
}

cat > "$OUT/ca.ext" <<'EOF'
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
cat > "$OUT/int.ext" <<'EOF'
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF
cat > "$OUT/leaf.ext" <<'EOF'
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOF

# make_chain <name> <root-alg> <intermediate-alg> <leaf-alg>
make_chain() {
  local name=$1 ralg=$2 ialg=$3 lalg=$4 d="$OUT/$1"
  mkdir -p "$d"
  echo "== building $name  (root=$ralg  int=$ialg  leaf=$lalg)"
  genkey "$ralg" "$d/root.key"
  $OPENSSL req -x509 -new -key "$d/root.key" -subj "/O=PQ Lab/CN=$name Root CA" \
      -days 3650 -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign" -out "$d/root.crt"
  genkey "$ialg" "$d/int.key"
  $OPENSSL req -new -key "$d/int.key" -subj "/O=PQ Lab/CN=$name Issuing CA" -out "$d/int.csr"
  $OPENSSL x509 -req -in "$d/int.csr" -CA "$d/root.crt" -CAkey "$d/root.key" \
      -CAcreateserial -days 1825 -extfile "$OUT/int.ext" -out "$d/int.crt" 2>/dev/null
  genkey "$lalg" "$d/leaf.key"
  $OPENSSL req -new -key "$d/leaf.key" -subj "/CN=localhost" -out "$d/leaf.csr"
  $OPENSSL x509 -req -in "$d/leaf.csr" -CA "$d/int.crt" -CAkey "$d/int.key" \
      -CAcreateserial -days 90 -extfile "$OUT/leaf.ext" -out "$d/leaf.crt" 2>/dev/null
  cat "$d/leaf.crt" "$d/int.crt" > "$d/chain.pem"          # what a TLS server sends
  $OPENSSL verify -CAfile "$d/root.crt" -untrusted "$d/int.crt" "$d/leaf.crt"
}

make_chain classical EC-P256 EC-P256 EC-P256
make_chain pq        ML-DSA-87 ML-DSA-65 ML-DSA-65
make_chain slhroot   SLH-DSA-SHA2-128s ML-DSA-65 ML-DSA-65
make_chain slhfull   SLH-DSA-SHA2-128s SLH-DSA-SHA2-128s SLH-DSA-SHA2-128s

der() { $OPENSSL x509 -in "$1" -outform DER | wc -c; }

echo
echo "=== Certificate sizes (DER bytes) ==="
printf "%-10s %8s %8s %8s %14s\n" chain root int leaf "sent in TLS*"
for n in classical pq slhroot slhfull; do
  r=$(der $OUT/$n/root.crt); i=$(der $OUT/$n/int.crt); l=$(der $OUT/$n/leaf.crt)
  printf "%-10s %8d %8d %8d %14d\n" "$n" "$r" "$i" "$l" $((i + l))
done
echo "* TLS sends leaf + intermediate. The root is already in the client trust store."
echo "  Note 'slhroot': the root cert itself never travels, but its large SLH-DSA SIGNATURE"
echo "  sits on the intermediate, which does. A hash-based root buys conservatism at the price"
echo "  of extra bytes in every handshake (compare pq vs slhroot above)."

echo
echo "=== Key sizes (leaf) ==="
for n in classical pq slhfull; do
  pub=$($OPENSSL pkey -in $OUT/$n/leaf.key -pubout -outform DER | wc -c)
  echo "$n: public key (SPKI DER) = $pub bytes"
done

echo
echo "=== Revocation: CRL signed by the issuing CA ==="
make_crl() {
  local n=$1 d="$OUT/$1/ca"
  mkdir -p "$d/newcerts"; : > "$d/index.txt"; echo 1000 > "$d/serial"; echo 01 > "$d/crlnumber"
  cat > "$d/ca.cnf" <<EOF
[ca]
default_ca = CA_default
[CA_default]
database = $d/index.txt
new_certs_dir = $d/newcerts
serial = $d/serial
crlnumber = $d/crlnumber
certificate = $OUT/$n/int.crt
private_key = $OUT/$n/int.key
default_md = default
default_crl_days = 7
policy = pol
unique_subject = no
[pol]
commonName = supplied
EOF
  $OPENSSL ca -config "$d/ca.cnf" -revoke "$OUT/$n/leaf.crt" >/dev/null 2>&1
  $OPENSSL ca -config "$d/ca.cnf" -gencrl -out "$OUT/$n/int.crl" >/dev/null 2>&1
  size=$($OPENSSL crl -in "$OUT/$n/int.crl" -outform DER | wc -c)
  res=$($OPENSSL verify -crl_check -CRLfile "$OUT/$n/int.crl" -CAfile "$OUT/$n/root.crt" \
        -untrusted "$OUT/$n/int.crt" "$OUT/$n/leaf.crt" 2>&1 | tr '\n' ' ' | cut -c1-120 || true)
  printf "%-10s CRL (1 revoked entry) = %5d bytes | verify says: %s\n" "$n" "$size" "$res"
}
make_crl classical
make_crl pq

echo
echo "Done. Files are in ./$OUT/<chain>/ (root.crt int.crt leaf.crt chain.pem *.key)"
echo "Next: inspect with   $OPENSSL x509 -in $OUT/pq/leaf.crt -noout -text | head -40"
