import sys
from cmroutine import cmMenu

def menuInicial():
    print("========== Menu Inicial - Tipo de scan ==========")
    print("[1] TCP")
    print("[2] UDP")
    print("[0] Sair")

    opcao = input("Escolha uma opcao: ")

    if opcao == "1":
        cmMenu("tcp")
    elif opcao == "2":
        cmMenu("ucp")
    elif opcao == "0":
        sys.exit()
    else:
        menuInicial()

if __name__ == '__main__':
    menuInicial()


