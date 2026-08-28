from tcproutine import tcpPKGdesigner
from udproutine import udpPKGdesigner

def cmMenu(scanType):
    print("===== Informacoes basicas do Scan =====")
    iptarget = input("Digite o IP target/domain - para range digite networkIP/xxx: ")
    tout = int(input("Informe o tempo (em segundos) de espera da resposta de cada pacote: "))
    tgap = int(input("Forneca o tempo (em segundos) entre os envios de cada pacote: "))
    pkgamount = int(input("Diga a quantidade de pacotes a serem enviados para cada porta: "))

    if scanType == "tcp":
        tcpPKGdesigner(iptarget,tout,tgap,pkgamount)
    else:
        udpPKGdesigner(iptarget,tout,tgap)
