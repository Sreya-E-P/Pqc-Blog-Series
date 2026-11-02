#!/usr/bin/env bash
# Lab 9 - Look at a post-quantum TLS 1.3 handshake in Wireshark / tshark
#
# What it does
#   1. Starts an OpenSSL TLS 1.3 server for 4 configurations (classical, hybrid, hybrid+ML-DSA,
#      bigger hybrid), captures each handshake with tcpdump on the loopback interface.
#   2. Estimates how many packets each message would need on a real 1500-byte Ethernet link.
#      (Loopback captures show merged 'super packets', so we calculate this ourselves.)
#   3. Saves the TLS session keys (-keylogfile) so Wireshark can DECRYPT the handshake.
#      (In TLS 1.3 the Certificate message is encrypted. Without keys you cannot see it.)
#   4. Uses tshark to print: ClientHello details, packet-by-packet sizes, and the size of
#      every handshake message.
#
# Needs: OpenSSL >= 3.5, tcpdump, tshark (sudo apt install tcpdump tshark), the PKI from 02_pki_lab.sh
#
#   bash 02_pki_lab.sh                      # once, creates ./pki
#   OPENSSL=/path/to/openssl bash 09_wireshark_lab.sh
#
# Open any capture later in the Wireshark GUI:
#   wireshark captures/hybrid_mldsa.pcap
#   Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename = captures/hybrid_mldsa.keys
set -uo pipefail

OPENSSL=${OPENSSL:-openssl}
PKI=${PKI:-pki}
PORT=${PORT:-4433}
OUT=${OUT:-captures}
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
mkdir -p "$OUT"

for t in tcpdump tshark; do
  command -v $t >/dev/null || { echo "missing $t:  sudo apt install tcpdump tshark"; exit 1; }
done
[ -d "$PKI/pq" ] || { echo "run 'bash 02_pki_lab.sh' first (needs OpenSSL >= 3.5)"; exit 1; }

cleanup() { pkill -x tcpdump 2>/dev/null; }
trap cleanup EXIT
echo "OpenSSL: $($OPENSSL version)"

capture() {   # capture <name> <groups> <chain>
  local name=$1 groups=$2 chain=$3
  rm -f "$OUT/$name.keys"
  $OPENSSL s_server -accept "$PORT" -tls1_3 -cert "$PKI/$chain/leaf.crt" -key "$PKI/$chain/leaf.key" \
      -cert_chain "$PKI/$chain/int.crt" -groups "$groups" -num_tickets 0 -www -quiet >/dev/null 2>&1 &
  local sp=$!
  sleep 0.7
  $SUDO tcpdump -i lo -U -w "$OUT/$name.pcap" "tcp port $PORT" >/dev/null 2>&1 &
  local tp=$!
  sleep 0.8
  $OPENSSL s_client -connect "127.0.0.1:$PORT" -tls1_3 -groups "$groups" -CAfile "$PKI/$chain/root.crt" \
      -verify_hostname localhost -keylogfile "$OUT/$name.keys" </dev/null >/dev/null 2>&1
  sleep 0.6
  $SUDO kill -INT $tp 2>/dev/null; wait $tp 2>/dev/null
  kill $sp 2>/dev/null; wait $sp 2>/dev/null
  $SUDO chmod a+r "$OUT/$name.pcap" 2>/dev/null
}

tsh() { tshark "$@" 2>/dev/null; }

analyze() {   # analyze <name> <title>
  local name=$1 title=$2
  local pcap="$OUT/$name.pcap" keys="$OUT/$name.keys"
  echo
  echo "=================================================================="
  echo " $title"
  echo "=================================================================="

  echo "-- 1) ClientHello (what the client offers)"
  tsh -r "$pcap" -Y "tls.handshake.type == 1" -T fields \
      -e frame.len -e tls.handshake.length -e tls.handshake.extensions_key_share_group \
      -e tls.handshake.extensions_key_share_key_exchange_length | \
    awk -F'\t' '{printf "   frame on the wire: %s bytes | handshake message: %s bytes | key_share group id(s): %s | share size(s): %s\n",$1,$2,$3,$4}'
  echo "   (group 29 = X25519, 4587 = 0x11EB = SecP256r1MLKEM768, 4588 = 0x11EC = X25519MLKEM768, 4589 = 0x11ED = SecP384r1MLKEM1024)"

  echo "-- 2) TCP data sent, and how many 1500-byte Ethernet packets that would be"
  echo "      (a normal Ethernet packet carries at most about 1448 bytes of TLS data)"
  tsh -r "$pcap" -Y "tcp.len > 0" -T fields -e frame.number -e tcp.srcport -e tcp.len | \
    awk -F'\t' -v p="$PORT" '{d=($2==p)?"server->client":"client->server"; e=int(($3+1447)/1448);
        printf "   capture pkt %-3s %-14s %6d bytes  ->  about %2d Ethernet packet(s)\n",$1,d,$3,e;
        if($2==p){s+=$3}else{c+=$3}}
        END{printf "   TOTAL  client->server: %d bytes (~%d packets) | server->client: %d bytes (~%d packets) | all: %d bytes\n",c,int((c+1447)/1448),s,int((s+1447)/1448),c+s}'

  echo "-- 3) Handshake messages, decrypted with the key log"
  tsh -r "$pcap" -o "tls.keylog_file:$keys" -Y "tls.handshake.type" -T fields \
      -e tcp.srcport -e tls.handshake.type -e tls.handshake.length | \
    awk -F'\t' -v p="$PORT" '
      function nm(t){return (t==1)?"ClientHello":(t==2)?"ServerHello":(t==8)?"EncryptedExtensions":(t==11)?"Certificate":(t==15)?"CertificateVerify":(t==20)?"Finished":"type"t}
      {n=split($2,t,","); split($3,l,","); for(i=1;i<=n;i++){printf "   %-14s %-20s %6d bytes\n",($1==p)?"server->client":"client->server",nm(t[i]),l[i]}}'
}

capture classical        X25519             classical
capture hybrid_ecdsa     X25519MLKEM768     classical
capture hybrid_mldsa     X25519MLKEM768     pq
capture big_hybrid_mldsa SecP384r1MLKEM1024 pq

analyze classical        "A. Classical: X25519 key exchange + ECDSA certificates"
analyze hybrid_ecdsa     "B. Hybrid X25519MLKEM768 key exchange + ECDSA certificates"
analyze hybrid_mldsa     "C. Hybrid X25519MLKEM768 key exchange + ML-DSA certificates"
analyze big_hybrid_mldsa "D. Bigger hybrid SecP384r1MLKEM1024 + ML-DSA certificates"

echo
echo "Capture files are in ./$OUT/  (*.pcap = packets, *.keys = session secrets: DELETE them when done, they decrypt the traffic)"
echo "Open one in Wireshark:  wireshark $OUT/hybrid_mldsa.pcap"
echo "Then try the display filters from the blog post (tls.handshake.type == 1 and so on)."
