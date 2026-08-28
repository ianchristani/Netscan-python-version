from scapy.all import sr
from scapy.layers.inet import IP, fragment, TCP
import time
from tcpclassifier import classificarResultados, imprimirResultados
from scapy.volatile import RandShort


def tcpSender(tout, tgap, pkgamount, fragPckg, package):
    resultados = []

    for count in range(pkgamount):
        if fragPckg:
            fragmentos = fragment(package, fragsize=24)
            answer = sr(fragmentos, timeout=tout, verbose=1)
            print(answer)
        else:
            answer = sr(package, timeout=tout, verbose=1)
            print(answer)
        resultados.append(answer)
        time.sleep(tgap)

    return resultados

# funcao de tratamento de entrada de portas
def parsearPortas(entrada, default):
    if default is True:
        default = list(range(1, 1025))

    entrada = entrada.strip()

    if entrada == "":
        return default
    portas = set()
    try:
        for parte in entrada.split(","):
            parte = parte.strip()
            if "-" in parte:
                inicio, fim = parte.split("-")
                inicio, fim = int(inicio.strip()), int(fim.strip())
                portas.update(range(inicio, fim + 1))
            else:
                portas.add(int(parte))
    except ValueError:
        print("Formato de porta(s) inválido. Usando faixa default 1-1024.")
        return default
    return sorted(portas)


# funcao de design de pacote
def tcpPKGdesigner(iptarget,tout,tgap,pkgamount):
    print("----- Informacoes do Scan TCP -----")
    print("""
                Sobre as portas a serem verificadas:
                Portas validas: 1 a 65535
                Se for 1 porta, apenas forneca-a;
                Se for mais de 1, digite-as separando por virgulas;
                Se for mais de 1, em sequencia, declare como (primeira-ultima).

                O nao fornecimento de portas, sera usado o default: 1 a 1024.

            """)
    entrada = input("Digite a(s) porta(s) a serem scanneadas: ")
    portas = parsearPortas(entrada, default = True)
        
    entrada = input("Fragmenta os pacotes - True/False - Default = False: ").strip().lower()
    fragPckg = entrada == "true"
    
    print("""
            Flags para compor os pacotes:
             S. SYN 
             A. ACK 
             F. FIN 
             R. RST (reset)
             P. PSH (push)
             U. URG (urgent)
             E. ECE (echo de controle de congestionamento)
             C. CWR (Congestion Window Reduced - resposta a flag anterior)             
        """)

    flag_raw = input("Forneca a(s) flag(s) a ser(em) usada(s), mais de uma, podem ser escritas juntas"
                     "- Default = sem flag, o que resulta em um scan do tipo NULL: ")
    flag = flag_raw.upper()

    # aqui montamos separados por camadas
    package = IP(dst=iptarget) / TCP(sport=RandShort(), dport=portas, flags=flag)

    resultados = tcpSender(tout,tgap,pkgamount,fragPckg,package)

    # rotulacao dos resultados
    if flag == "S":
        fase = "syn_scan"
    elif flag == "":
        fase = "null_scan"
    elif flag == "F":
        fase = "fin_scan"
    elif set(flag) == {"F", "P", "U"}:
        fase = "xmas_scan"
    else:
        fase = "custom_scan"

    status_portas = classificarResultados(resultados, flag=flag, protocolo="tcp", fase=fase)

    # closed so e confiavel em scan SYN puro
    ocultar_closed = (flag == "S")

    print("\n----- Resultado do Scan TCP -----")
    imprimirResultados(status_portas, iptarget, protocolo="tcp", ocultar_closed=ocultar_closed)

    print("\n----- Resultado em formato dict -----")
    print(status_portas)

    return status_portas   
    