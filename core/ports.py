import json
import masscan

def _extract_ports(target): 

    """
    Restituisce una lista di porte aperte, estratta dall'output
    di una scansione di MASSCAN

    Args:
        target (str): Indirizzo da scansionare con masscan

    Returns:
        list: Lista di output
    """

    mas = masscan.PortScanner()
    mas.scan(target, ports='20-100', arguments='--rate 100 --wait 5')
    res = json.loads(mas.scan_result)

    open_ports = sorted({e["port"]
                        for entries in res.get("scan", {}).values()
                        for e in entries
                        if e.get("status") == "open"})

    return(open_ports)

def extract_nmap(target):
    
    """
    Output pulito per futura scansione con nmap

    Args:
        a (str): Indirizzo da scansionare con masscan

    Returns:
        str: stringa di output contenente le porte aperte
    """

    port_string = ''
    oport_list = _extract_ports(target)
    lung = len(oport_list) - 1
    acc = 0
    
    for n in oport_list:
        if acc == lung:
            port_string +=str(n)
        else:
            port_string +=str(n) + ','
        acc+=1
    return port_string


