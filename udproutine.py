

def udpPKGdesigner(iptarget,tout,tgap,pkgamount):
    print("----- Informacoes do Scan UDP -----")
    print(""" 
                                        AVISO

                A Varredura UDP realizará a varredura seguindo as especificações:

                a. As portas UDP mais comuns serão consideradas:
                53, 67, 68, 69, 111, 123, 135, 137, 138, 139,
                161, 162, 177, 500, 514, 520, 623, 1434, 1900,
                4500, 5060, 5353

                b. Primeiro, o pacote terá um payload específico para a porta; se
                não houver resposta, um pacote sem o mesmo será enviado.

            """)

    # portsToBeScanned = None
    # report = executar_scan_udp(ipTarget, portsToBeScanned, waitingTime, pkgTime)

