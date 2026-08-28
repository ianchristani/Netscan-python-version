#!/usr/bin/python3

import sys
from cmroutine import cmMenu

def menuInicial():
    print("""
    ========== Menu Inicial - Tipo de scan ==========
    Os scan do tipo Connect (muito invasivo) e Discover (use ICMP) nao sao suportados.

    Escolha o tipo de protocolo:
    [1] TCP
    [2] UDP
    [0] Sair
    """)

    opcao = input("Escolha uma opcao: ")

    if opcao == "1":
        cmMenu("tcp")
    elif opcao == "2":
        cmMenu("udp")
    elif opcao == "0":
        sys.exit()
    else:
        print("Opcao invalida!")
        menuInicial()

if __name__ == '__main__':
    menuInicial()


