import os
import re
import datetime
from itertools import chain
from pathlib import Path
from pyfiglet import Figlet
from core.csv_to_dict import extract_data
from core.core_dataflow import process_target


def main():
    
    #stampa banner iniziiiale nella console
    f = Figlet(font='eftifont')
    print(f.renderText('AUTOSCANN3R'))

    #Blocco per gli input iniziali del nome dell'utente e della sua organizzazione
    print('[*] Inserisci il tuo nome:')
    owner_nome = input()
    print('[*] Inserisci il nome della tua organizzazione:')
    org_name = input()
    
    #Carica i target da scannerizzare
    entries = extract_data()

    #Controlla, prima di proseguire con la scansione, se è presente almeno un target
    if not entries:
        raise Exception("Il foglio con i target sembra essere vuoto, controlla il README in caso di dubbi!") 
    
    for entry in entries:
        titolo = (entry.get("Titolo")).strip()
        indirizzi = list(dict.fromkeys((entry.get("Indirizzi"))))
        
        if not titolo or not indirizzi:
            raise Exception("Il foglio con i target sembra avere problemi, controlla il README in caso di dubbi!")

        #Esegue lo script completo per ogni istanza del file dei target
        for ip in indirizzi:
            path = process_target(titolo, ip, owner_nome, org_name)
            print(f'[*] Report "{titolo}" pronto! Consultalo nella directory "/reports"')

if __name__ == "__main__":
    main()
