#!/usr/bin/env bash
set -u

DC_IP="${DC_IP:-192.168.1.10}"
DC_HOST="${DC_HOST:-kingslanding.sevenkingdoms.local}"
DC_SHORT="${DC_SHORT:-${DC_HOST%%.*}}"
DOMAIN="${DOMAIN:-sevenkingdoms.local}"
REALM="${REALM:-SEVENKINGDOMS.LOCAL}"
BASE_DN="${BASE_DN:-dc=sevenkingdoms,dc=local}"
WORKGROUP="${WORKGROUP:-SEVENKINGDOMS}"
LOG_FILE="${LOG_FILE:-/home/adadmin/ada-ad-traffic.log}"
LOCK_FILE="${LOCK_FILE:-/tmp/ada-ad-traffic.lock}"
TIMEOUT="${TIMEOUT:-5}"

mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
  exit 0
fi

ts() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
  printf '%s %s\n' "$(ts)" "$*" >>"$LOG_FILE"
}

run() {
  local label="$1"
  shift
  log "RUN $label :: $*"
  timeout "$TIMEOUT" "$@" >>"$LOG_FILE" 2>&1 || true
}

have() {
  command -v "$1" >/dev/null 2>&1
}

reverse_name_for_dc() {
  awk -v ip="$DC_IP" 'BEGIN { split(ip, a, "."); printf "%s.%s.%s.%s.in-addr.arpa", a[4], a[3], a[2], a[1] }'
}

run_dns() {
  if ! have dig; then
    return
  fi
  local ptr
  ptr="$(reverse_name_for_dc)"
  local queries=(
    "$DOMAIN SOA"
    "$DOMAIN NS"
    "$DOMAIN A"
    "$DC_HOST A"
    "$ptr PTR"
    "_ldap._tcp.$DOMAIN SRV"
    "_ldap._tcp.dc._msdcs.$DOMAIN SRV"
    "_ldap._tcp.pdc._msdcs.$DOMAIN SRV"
    "_ldap._tcp.gc._msdcs.$DOMAIN SRV"
    "_ldap._tcp.Default-First-Site-Name._sites.$DOMAIN SRV"
    "_kerberos._tcp.$DOMAIN SRV"
    "_kerberos._udp.$DOMAIN SRV"
    "_kerberos._tcp.Default-First-Site-Name._sites.$DOMAIN SRV"
    "_kpasswd._tcp.$DOMAIN SRV"
    "_kpasswd._udp.$DOMAIN SRV"
    "_gc._tcp.$DOMAIN SRV"
    "_msdcs.$DOMAIN NS"
    "DomainDnsZones.$DOMAIN A"
    "ForestDnsZones.$DOMAIN A"
  )
  local q name qtype
  for q in "${queries[@]}"; do
    name="${q% *}"
    qtype="${q##* }"
    run "dns:$qtype:$name" dig "@$DC_IP" "$name" "$qtype" +time=2 +tries=1 +noall +answer
  done
}

run_ldap() {
  if ! have ldapsearch; then
    return
  fi
  local ldap_uri="ldap://$DC_IP"
  local ldaps_uri="ldaps://$DC_IP"
  local ldaps_gc_uri="ldaps://$DC_IP:3269"
  run "ldap:rootdse:naming" ldapsearch -x -H "$ldap_uri" -o nettimeout=3 -l 4 -s base -b "" namingContexts defaultNamingContext supportedLDAPVersion dnsHostName
  run "ldap:rootdse:sasl" ldapsearch -x -H "$ldap_uri" -o nettimeout=3 -l 4 -s base -b "" supportedSASLMechanisms supportedCapabilities
  run "ldap:base:domain" ldapsearch -x -H "$ldap_uri" -o nettimeout=3 -l 4 -s base -b "$BASE_DN" objectClass distinguishedName objectSid
  LDAPTLS_REQCERT=never run "ldap:ldaps:rootdse" ldapsearch -x -H "$ldaps_uri" -o nettimeout=3 -l 4 -s base -b "" namingContexts dnsHostName
  LDAPTLS_REQCERT=never run "ldap:ldaps-gc:rootdse" ldapsearch -x -H "$ldaps_gc_uri" -o nettimeout=3 -l 4 -s base -b "" namingContexts dnsHostName

  local filters=(
    "(objectClass=domainDNS)"
    "(objectClass=computer)"
    "(objectClass=user)"
    "(objectClass=group)"
    "(objectClass=organizationalUnit)"
    "(objectCategory=person)"
    "(sAMAccountName=Administrator)"
    "(sAMAccountName=Guest)"
    "(primaryGroupID=516)"
    "(userAccountControl:1.2.840.113556.1.4.803:=512)"
    "(servicePrincipalName=*)"
    "(adminCount=1)"
    "(memberOf=*)"
    "(cn=Domain Controllers)"
    "(dNSHostName=$DC_HOST)"
  )
  local filter
  for filter in "${filters[@]}"; do
    run "ldap:search:$filter" ldapsearch -x -H "$ldap_uri" -o nettimeout=3 -l 4 -z 5 -s sub -b "$BASE_DN" "$filter" dn cn sAMAccountName dNSHostName
  done
}

run_kerberos() {
  if ! have kinit; then
    return
  fi
  local krb_conf="/tmp/ada-ad-traffic-krb5.conf"
  cat >"$krb_conf" <<EOF
[libdefaults]
 default_realm = $REALM
 dns_lookup_realm = false
 dns_lookup_kdc = false
 udp_preference_limit = 1
[realms]
 $REALM = {
  kdc = $DC_IP
  admin_server = $DC_IP
 }
[domain_realm]
 .$DOMAIN = $REALM
 $DOMAIN = $REALM
EOF
  local principals=(
    "ada_probe_user_01"
    "ada_probe_user_02"
    "ada_probe_admin_01"
    "ada_probe_admin_02"
    "ada_probe_svc_ldap/$DC_HOST"
    "ada_probe_svc_host/$DC_HOST"
    "ada_probe_svc_cifs/$DC_HOST"
    "ada_probe_svc_dns/$DC_HOST"
    "ada_probe_svc_gc/$DC_HOST"
    "ada_probe_svc_http/$DC_HOST"
    "ada_probe_svc_mssql/$DC_HOST"
    "ada_probe_svc_rdp/$DC_HOST"
    "ada_probe_svc_dfsr/$DC_HOST"
    "ada_probe_svc_backup/$DC_HOST"
    "ada_probe_svc_sync/$DC_HOST"
  )
  local principal
  for principal in "${principals[@]}"; do
    printf 'not-the-password\n' | KRB5_CONFIG="$krb_conf" timeout "$TIMEOUT" kinit "$principal@$REALM" >>"$LOG_FILE" 2>&1 || true
  done
}

run_smb() {
  if ! have smbclient; then
    return
  fi
  local targets=("$DC_IP" "$DC_HOST")
  local target
  for target in "${targets[@]}"; do
    run "smb:list:$target:anon" smbclient -L "//$target" -N -m SMB3
    run "smb:list:$target:baduser" smbclient -L "//$target" -U "ADA_PROBE%not-the-password" -m SMB3
  done
  local shares=("IPC$" "SYSVOL" "NETLOGON" "C$" "ADMIN$" "print$")
  local share
  for share in "${shares[@]}"; do
    run "smb:share:$share:anon" smbclient "//$DC_IP/$share" -N -m SMB3 -c 'pwd;ls'
    run "smb:share:$share:baduser" smbclient "//$DC_IP/$share" -U "ADA_PROBE%not-the-password" -m SMB3 -c 'pwd;ls'
  done
}

run_rpcclient() {
  if ! have rpcclient; then
    return
  fi
  local rpc_cmds=(
    "srvinfo"
    "lsaquery"
    "querydominfo"
    "enumdomusers"
    "enumdomgroups"
    "enumalsgroups builtin"
    "lookupnames Administrator"
    "lookupsids S-1-5-32-544"
    "getdompwinfo"
    "getusername"
    "netshareenumall"
    "netsharegetinfo SYSVOL"
    "dsroledominfo"
    "lsaenumsid"
    "enumprivs"
    "querydispinfo"
    "lookupnames Guest"
    "samlookupnames domain Administrator"
  )
  local cmd
  for cmd in "${rpc_cmds[@]}"; do
    run "rpcclient:$cmd" rpcclient -U "" -N "$DC_IP" -c "$cmd"
  done
}

run_netbios() {
  if have nmblookup; then
    run "nbns:node-status" nmblookup -A "$DC_IP"
    run "nbns:dc-host" nmblookup "$DC_SHORT"
    run "nbns:domain" nmblookup "$WORKGROUP"
  fi
  python3 - "$DC_IP" "$WORKGROUP" "$DC_HOST" >>"$LOG_FILE" 2>&1 <<'PY' || true
import random
import socket
import struct
import sys
import time

dc_ip, workgroup, dc_host = sys.argv[1], sys.argv[2], sys.argv[3].split(".")[0]

def encode_name(name, suffix):
    raw = (name.upper()[:15].ljust(15) + chr(suffix)).encode("ascii", "ignore")
    out = bytearray([32])
    for b in raw:
        out.append(ord("A") + ((b >> 4) & 0x0f))
        out.append(ord("A") + (b & 0x0f))
    out.append(0)
    return bytes(out)

names = [
    (dc_host, 0x00),
    (dc_host, 0x20),
    (workgroup, 0x00),
    (workgroup, 0x1b),
    (workgroup, 0x1c),
    (workgroup, 0x1d),
    ("*", 0x00),
    ("ADMINISTRATOR", 0x00),
    ("ADA-PROBE", 0x00),
    ("WINTERFELL", 0x00),
]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1.0)
for name, suffix in names:
    tid = random.randint(0, 65535)
    qtype = 0x0021 if name == "*" else 0x0020
    pkt = struct.pack(">HHHHHH", tid, 0x0010, 1, 0, 0, 0)
    pkt += encode_name(name, suffix) + struct.pack(">HH", qtype, 1)
    try:
        s.sendto(pkt, (dc_ip, 137))
        s.recvfrom(4096)
    except Exception:
        pass
    time.sleep(0.05)
PY
}

run_raw_dcerpc_and_rdp() {
  python3 - "$DC_IP" "$DC_HOST" >>"$LOG_FILE" 2>&1 <<'PY' || true
import socket
import struct
import sys
import time
import uuid

dc_ip, dc_host = sys.argv[1], sys.argv[2]

NDR_UUID = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
interfaces = [
    ("epm", "e1af8308-5d1f-11c9-91a4-08002b14a0fa", 3),
    ("svcctl", "367abb81-9844-35f1-ad32-98f038001003", 2),
    ("srvsvc", "4b324fc8-1670-01d3-1278-5a47bf6ee188", 3),
    ("lsarpc", "12345778-1234-abcd-ef00-0123456789ab", 0),
    ("samr", "12345778-1234-abcd-ef00-0123456789ac", 1),
    ("netlogon", "12345678-1234-abcd-ef00-01234567cffb", 1),
    ("drsuapi", "e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4),
    ("winreg", "338cd001-2244-31f1-aaaa-900038001003", 1),
    ("wkssvc", "6bffd098-a112-3610-9833-46c3f87e345a", 1),
    ("atsvc", "1ff70682-0a51-30e8-076d-740be8cee98b", 1),
    ("efsrpc", "c681d488-d850-11d0-8c52-00c04fd90f7e", 1),
    ("spoolss", "12345678-1234-abcd-ef00-0123456789ab", 1),
    ("eventlog", "82273fdc-e32a-18c3-3f78-827929dc23ea", 0),
    ("tasksched", "86d35949-83c9-4044-b424-db363231fd0c", 1),
    ("iremote_scm", "000001a0-0000-0000-c000-000000000046", 0),
]

def syntax_id(u, version):
    return uuid.UUID(u).bytes_le + struct.pack("<I", version)

def bind_pdu(interface_uuid, version, call_id):
    abstract = syntax_id(interface_uuid, version)
    transfer = NDR_UUID.bytes_le + struct.pack("<I", 2)
    body = struct.pack("<HHIBBH", 4280, 4280, 0, 1, 0, 0)
    body += struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    frag_len = 16 + len(body)
    header = struct.pack("<BBBBIHHI", 5, 0, 11, 3, 0x10, frag_len, 0, call_id)
    return header + body

def send_rpc_bind(port, name, interface_uuid, version, call_id):
    try:
        with socket.create_connection((dc_ip, port), timeout=2.0) as s:
            s.settimeout(2.0)
            s.sendall(bind_pdu(interface_uuid, version, call_id))
            try:
                s.recv(4096)
            except socket.timeout:
                pass
    except Exception:
        pass
    time.sleep(0.05)

call_id = 1
for port in (135, 593):
    for name, interface_uuid, version in interfaces:
        send_rpc_bind(port, name, interface_uuid, version, call_id)
        call_id += 1

def send_rdp_probe(label):
    cookie = f"Cookie: mstshash={label}\r\n".encode()
    nego = b"\x01\x00\x08\x00\x03\x00\x00\x00"
    x224_len = 6 + len(cookie) + len(nego)
    pkt = struct.pack(">BBH", 3, 0, 4 + x224_len)
    pkt += bytes([x224_len - 1, 0xe0, 0, 0, 0, 0])
    pkt += cookie + nego
    try:
        with socket.create_connection((dc_ip, 3389), timeout=2.0) as s:
            s.settimeout(2.0)
            s.sendall(pkt)
            try:
                s.recv(4096)
            except socket.timeout:
                pass
    except Exception:
        pass

for label in ["ada", "admin", "svc", "ldap", "kerb", "rpc", "smb", "dc", "probe", "bzar"]:
    send_rdp_probe(label)
    time.sleep(0.05)
PY
}

run_encrypted_ad_service_probes() {
  python3 - "$DC_IP" "$DC_HOST" >>"$LOG_FILE" 2>&1 <<'PY' || true
import socket
import ssl
import sys
import time

dc_ip, dc_host = sys.argv[1], sys.argv[2]

def tcp_probe(port, payload=b"", timeout=2.0):
    try:
        with socket.create_connection((dc_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
                try:
                    s.recv(1024)
                except Exception:
                    pass
    except Exception:
        pass
    time.sleep(0.05)

def tls_probe(port, server_name):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((dc_ip, port), timeout=2.0) as raw:
            raw.settimeout(2.0)
            with ctx.wrap_socket(raw, server_hostname=server_name) as ssock:
                try:
                    ssock.recv(1)
                except Exception:
                    pass
    except Exception:
        pass
    time.sleep(0.05)

wsman_body = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b'<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
    b'<s:Header/><s:Body/></s:Envelope>'
)
wsman_http = (
    b"POST /wsman HTTP/1.1\r\n"
    + f"Host: {dc_host}:5985\r\n".encode()
    + b"User-Agent: Microsoft WinRM Client\r\n"
    + b"Content-Type: application/soap+xml;charset=UTF-8\r\n"
    + f"Content-Length: {len(wsman_body)}\r\n".encode()
    + b"Connection: close\r\n\r\n"
    + wsman_body
)

for _ in range(3):
    tcp_probe(5985, wsman_http)
    tls_probe(5986, dc_host)
    tcp_probe(9389)
    tls_probe(636, dc_host)
    tls_probe(3269, dc_host)
PY
}

main() {
  log "START dc=$DC_IP host=$DC_HOST domain=$DOMAIN"
  run_dns
  run_ldap
  run_kerberos
  run_smb
  run_rpcclient
  run_netbios
  run_raw_dcerpc_and_rdp
  run_encrypted_ad_service_probes
  log "DONE"
}

main "$@"
