import re


class Organizer:
    """
    Pulisce e normalizza i risultati di scansione in coppie (product, version)
    
    Args:
        lista (list): Lista di dizionari con chiavi come 'host', 'port', 'product', 'service_version'.
    """

    def __init__(self, lista):
        """
        Inizializza l'organizer con la lista grezza di risultati.

        Args:
            lista (list): Lista di dizionari (es. output di NmapScanner).
        """

        self.lista = lista
        self.organized_list = []
        self.true_organized_list = []
        self.clean_list = []
        self.lista_finale = []
        self.h = "host"
        self.p = "port"
        self.pr = "product"
        self.v = "service_version"

    def _retriever(self):
        """
        Estrae tuple (host, port, product, service_version) dagli elementi della lista.

        Returns:
            list: Lista di tuple (host, port, product, service_version).
        """

        self.reset_output(self.organized_list)
        for n in self.lista:
            if self.h in n and self.p in n and self.pr in n and self.v in n:
                self.organized_list.append((n[self.h], n[self.p], n[self.pr], n[self.v]))

        return self.organized_list

    def true_retriever(self):
        """
        Estrae solo le coppie (product, service_version) dalla lista di input

        """

        self.reset_output(self.true_organized_list)
        for n in self.lista:
            if self.pr in n and self.v in n:
                self.true_organized_list.append((n[self.pr], n[self.v]))

    def cleansing(self):
        """
        Pulizia e normalizzazione delle coppie (product, version)

        Returns:
            list: Lista output con tuple (product, versione_normalizzata).
        """

        self.true_retriever()
        self.reset_output(self.clean_list)
        for a, b in self.true_organized_list:
            if (a not in ("", None)) and (b not in ("", None)):
                self.clean_list.append((a, b))
        self._version_ready(self.clean_list)

        return self.lista_finale

    def _version_ready(self, lista_cl):
        """
        Normalizza le versioni estraendo solo la parte numerica principale

        Args:
            lista_cl (list): Lista di tuple (product, version) da normalizzare.
        """

        self.reset_output(self.lista_finale)
        for a, b in lista_cl:
            #Estrae solo la parte numerica principale della versione
            b_true = re.search(r"\d+(?:\.\d+){0,2}", b)
            b1 = b_true.group(0) if b_true else b
            self.lista_finale.append((a, b1))

    def reset_output(self, lst):
        """
        Svuota lista

        Args:
            lst (list): Lista da svuotare
        """

        lst.clear()
