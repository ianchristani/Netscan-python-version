import scapy.all
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind
from scapy.asn1.asn1 import ASN1_OID


# Payloads nativos do Scapy - {porta: payload}
_PAYLOADS_SCAPY = {
    53:  DNS(rd=1, qd=DNSQR(qname="test.com")),                              # DNS query
    123: NTP(version=3, mode=3),                                            # NTP client request
    161: SNMP(community="public",
              PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID("1.3.6.1.2.1.1.1.0"))])),  # SNMP GetRequest
}

# Payloads em bytes crus (baseados no nmap-payloads) - {porta: payload}
_PAYLOADS_RAW = {
    67:   b"\x01\x01\x06\x00" + b"\x00" * 24,                                # DHCP Discover (simplificado)
    69:   b"\x00\x01" + b"test.txt\x00" + b"octet\x00",                      # TFTP RRQ
    111:  bytes.fromhex(
              "72fe1d130000000000000002000186a0000000020000000000000000"
              "0000000000000000000000000000000000000000000000000000"),      # RPC NULL call (portmapper)
    137:  bytes.fromhex(
              "82288010000100000000000020434b4141414141414141414141414141"
              "414141414141414141414141414141410000210001"),                 # NetBIOS Name Service query
    500:  b"\x00" * 28,                                                     # ISAKMP header genérico
    520:  b"\x01\x01" + b"\x00" * 22,                                        # RIP request
    1900: (b"M-SEARCH * HTTP/1.1\r\n"
           b"HOST: 239.255.255.250:1900\r\n"
           b"MAN: \"ssdp:discover\"\r\n"
           b"MX: 1\r\n"
           b"ST: ssdp:all\r\n\r\n"),                                        # SSDP/UPnP discover
    5353: bytes.fromhex(
              "000000000001000000000000075f73657276696365735f646e732d7364"
              "045f756470056c6f63616c00000c0001"),                          # mDNS query
    5060: (b"OPTIONS sip:test@example.com SIP/2.0\r\n"
           b"Via: SIP/2.0/UDP 127.0.0.1:5060\r\n"
           b"From: <sip:scanner@example.com>\r\n"
           b"To: <sip:test@example.com>\r\n"
           b"Call-ID: 12345\r\n"
           b"CSeq: 1 OPTIONS\r\n\r\n"),                                     # SIP OPTIONS
}

# Top ~20 portas UDP mais relevantes
TOP_UDP_PORTS = [53, 67, 68, 69, 111, 123, 135, 137, 138, 139,
                  161, 162, 177, 500, 514, 520, 623, 1434, 1900,
                  4500, 5060, 5353]

# escolha do payload
def get_udp_payload(porta: int):
    if porta in _PAYLOADS_SCAPY:
        return _PAYLOADS_SCAPY[porta]
    if porta in _PAYLOADS_RAW:
        return scapy.all.Raw(load=_PAYLOADS_RAW[porta])
    return scapy.all.Raw(load=b"")


# scan de porta primeiro com o payload, se nao tiver resposta, sem payload
def scan_udp_porta(alvo: str, porta: int, timeout: float = 2, tentar_sem_payload: bool = True):
    """
    Retorna uma tupla (estado, fase) onde:
      estado -> "open" | "closed" | "open|filtered" | "filtered"
      fase   -> "com_payload" | "sem_payload" (qual tentativa gerou o resultado)
    """
    from scapy.all import sr1, RandShort, ICMP

    def _enviar(pkt):
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp is None:
            return None
        if resp.haslayer(ICMP):
            icmp_type = int(resp[ICMP].type)
            icmp_code = int(resp[ICMP].code)
            if icmp_type == 3 and icmp_code == 3:
                return "closed"
            if icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
                return "filtered"
        if resp.haslayer(UDP):
            return "open"
        return "open|filtered"

    # com payload
    sport = RandShort()
    payload = get_udp_payload(porta)
    tem_payload_real = bytes(payload) != b""   # False se a porta caiu no fallback vazio

    pkt_com_payload = IP(dst=alvo) / UDP(dport=porta, sport=sport) / payload
    estado = _enviar(pkt_com_payload)

    if estado is not None:
        return estado, "com_payload"

    # sem payload
    if tentar_sem_payload and tem_payload_real:
        pkt_sem_payload = IP(dst=alvo) / UDP(dport=porta, sport=sport)
        estado = _enviar(pkt_sem_payload)
        if estado is not None:
            return estado, "sem_payload"

    # Nenhuma das duas teve resposta -> ambíguo (padrão de UDP scan)
    return "open|filtered", "sem_resposta"


def scan_portas_conhecidas(alvo: str, timeout: float = 2, tentar_sem_payload: bool = True):
    """
    Escaneia automaticamente TODAS as portas que têm payload mapeado
    (chaves de _PAYLOADS_SCAPY + _PAYLOADS_RAW), sem precisar informar
    porta por porta manualmente.

    Retorna um dicionário: {porta: (estado, fase)}
    """
    portas_com_payload = sorted(set(_PAYLOADS_SCAPY.keys()) | set(_PAYLOADS_RAW.keys()))

    resultados = {}
    for porta in portas_com_payload:
        resultados[porta] = scan_udp_porta(alvo, porta, timeout=timeout,
                                            tentar_sem_payload=tentar_sem_payload)
    return resultados


def executar_scan_udp(alvo: str, portas, timeout, inter):
    """
    Função final: executa o scan UDP em uma lista de portas.
    Para cada porta:
      1) Tenta 1 pacote COM payload (se a porta tiver payload mapeado).
      2) Se não houver resposta, tenta automaticamente 1 pacote SEM payload.

    Retorna um dicionário: {porta: {"estado": ..., "fase": ...}}
    """
    import time

    if portas is None:
        portas = TOP_UDP_PORTS

    resultados = {}
    for porta in portas:
        estado, fase = scan_udp_porta(alvo, porta, timeout=timeout, tentar_sem_payload=True)
        resultados[porta] = {"estado": estado, "fase": fase}
        print(f"[{alvo}] porta {porta:>5}/udp -> {estado:<15} (via {fase})")
        time.sleep(inter)

    return resultados
