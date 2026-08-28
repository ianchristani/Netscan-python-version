from scapy.layers.inet import TCP, ICMP

ICMP_FILTRADO_CODES = (1, 2, 3, 9, 10, 13)


def _e_syn_scan(flag):
    return flag.strip().upper() == "S"


def classificarResultados(resultados, flag, protocolo="tcp", fase="scan"):
    syn_scan = _e_syn_scan(flag)

    estado_por_porta = {}
    portas_com_resposta_tcp = set()
    todas_portas = set()

    for respostas, nao_respondidas in resultados:
        for enviado, recebido in respostas:
            porta = enviado[TCP].dport
            todas_portas.add(porta)

            if recebido.haslayer(TCP):
                tflags = str(recebido[TCP].flags)
                portas_com_resposta_tcp.add(porta)

                if syn_scan:
                    if "S" in tflags and "A" in tflags:
                        estado_por_porta[porta] = "open"
                    elif "R" in tflags:
                        estado_por_porta.setdefault(porta, "closed")
                else:
                    if "R" in tflags:
                        estado_por_porta.setdefault(porta, "closed")
                    elif porta not in estado_por_porta:
                        estado_por_porta[porta] = "open"

            elif recebido.haslayer(ICMP):
                icmp_type = recebido[ICMP].type
                icmp_code = recebido[ICMP].code
                if icmp_type == 3 and icmp_code in ICMP_FILTRADO_CODES:
                    estado_por_porta[porta] = "filtered"

        for pkt in nao_respondidas:
            porta = pkt[TCP].dport
            todas_portas.add(porta)

    sem_resposta = todas_portas - portas_com_resposta_tcp
    for porta in sem_resposta:
        if porta in estado_por_porta:
            continue
        estado_por_porta[porta] = "filtered"

    return {
        porta: {"estado": estado, "flag(s)": fase}
        for porta, estado in estado_por_porta.items()
    }


def formatarLinhas(status_portas, iptarget, protocolo="tcp", ocultar_closed=False):
    linhas = []
    for porta in sorted(status_portas.keys()):
        info = status_portas[porta]
        if ocultar_closed and info["estado"] == "closed":
            continue
        linhas.append(
            f"[{iptarget}] porta {porta}/{protocolo} -> {info['estado']}"
            f" (Flag(s) {info['flag(s)']})"
        )
    return linhas


def imprimirResultados(status_portas, iptarget, protocolo="tcp", ocultar_closed=False):
    for linha in formatarLinhas(status_portas, iptarget, protocolo, ocultar_closed):
        print(linha)