from scapy.all import Raw, sr1, send, AsyncSniffer, sr
from scapy.layers.inet import IP, fragment
import random,time


# funcao de envio de pacotes
# considerar o caso de portas randomicas que usara um for para criar as instancias gerando portas diferentes
# nesse caso a qde de pacotes entra como parametro do FOR em uma contagem
# se nao tiver porta randomica - a qde depacotes entra como parametro da funcao de envio
def tcpSender(tout,tgap,pkgamount,fragPckg,randport,package):
    if randport == True:
        for count in range (pkgamount):
            pass

    else:

        pass


# funcao de design de pacote
def tcpPKGdesigner(iptarget,tout,tgap,pkgamount):
    print("----- Informacoes do Scan TCP -----")
    print("""
                Sobre as portas a serem verificadas:
                Se for 1 porta, apenas forneca-a;
                Se for mais de 1, mas nao em sequencia, digite-as separando por virgulas;
                Se for mais de 1 em sequencia, digite a primeira e a ultima, mas separando-as por hifem (sem espacos).

            """)
    portas = input("Digite a(s) porta(s) a serem scanneadas: ")
    # aqui precisa de tratamento

    entrada = bool(input("Fragmenta os pacotes - True/False - Default = False: "))
    fragPckg = entrada if entrada != "" else False

    entrada = bool(input("Randomiza portas de envio - True/False - Default = True: "))
    randport = entrada if entrada != "" else True

    # incluir as flags
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

    # entrada da flag
    flag = input("Forneca a(s) flag(s) a ser(em) usada(s), separando por virgula "
                     "- Default = sem flag, o que resulta em um scan do tipo NULL: ")

    # aqui montamos separados por camadas
    package = IP(dst=iptarget) / TCP(dport=portas, flags=flag)

    tcpSender(tout,tgap,pkgamount,fragPckg,randport,package)