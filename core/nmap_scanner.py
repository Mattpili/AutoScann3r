import nmap


class NmapScanner:
    """
    Wrapper semplice attorno a `python-nmap` per eseguire una scansione Nmap su un target.

    
    Attributes:
        scanner (nmap.PortScanner): Istanza interna di PortScanner.
        entry_list (list): Lista di risultati (dict) generata da `run_scan`.
        target (str): Target da scansionare (es. IP o hostname).
        options (str): Stringa di argomenti da passare a Nmap (es. "-A -p 80,443").
    """

    def __init__(self, target: str, options: str) -> None:
        """
        Inizializza lo scanner Nmap per il target specificato.

        Args:
            target (str): Target da scansionare
            options (str): Opzioni da passare a Nmap.
        """

        self.scanner = nmap.PortScanner()
        self.entry_list = []
        self.target = target
        self.options = options

    def run_scan(self):
        """
        Esegue la scansione Nmap e restituisce i risultati in forma strutturata.

        Returns:
            list: Lista di dizionari, uno per ogni porta trovata
        """

        #Esecuzione della scansione Nmap con le opzioni specificate
        self.scanner.scan(self.target, arguments=self.options)

        #Salva i risultati della scansione in una lista di dizionari
        for host in self.scanner.all_hosts():
            #Rilevazione sistema operativo (se disponibile)
            operative_system = "Unknown"
            if "osmatch" in self.scanner[host]:
                operative_system = self.scanner[host]["osmatch"][0]["name"]

            for proto in self.scanner[host].all_protocols():
                for port in self.scanner[host][proto].keys():
                    service = self.scanner[host][proto][port]["name"]
                    version = self.scanner[host][proto][port]["version"]
                    prod = self.scanner[host][proto][port]["product"]

                    self.entry_list.append(
                        dict(
                            host=host,
                            os=operative_system,
                            protocol=proto,
                            port=port,
                            service_name=service,
                            service_version=version,
                            product=prod,
                        )
                    )
        return self.entry_list
