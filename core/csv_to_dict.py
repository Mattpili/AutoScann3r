from pathlib import Path
import csv


def extract_data():

    """ 
    Estrae i dati presenti nel file 'NOME_FILE_TARGETS' e restituisce una lista 
    di dizionari dalla forma: Chiave -> Titolo valore -> Indirizzo IP
    
    Returns:
        list: Lista di dizionari per ogni "coppia" Titolo:Indirizzo IP 
    """

    data = []
    #Cambiare nome del file csv a piacimento, targets.csv è quello predefinito e inizialmente vuoto
    NOME_FILE_TARGETS = "targets.csv"
    path = Path("targets") / NOME_FILE_TARGETS

    with path.open(newline="", encoding="utf-8") as file:
        reader = csv.reader(file, delimiter=";")
        for row in reader:
            if not row or row[0].strip().startswith("#"):
                continue
            titolo = row[0].strip()
            indirizzi = [x.strip() for x in row[1:] if x and x.strip()]
            data.append({"Titolo": titolo, "Indirizzi": indirizzi})

    return data

