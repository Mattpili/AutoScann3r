# AutoScann3r [WORK IN PROGRESS]

AutoScann3r è un strumento pensato per automatizzare la scansione di host tramite i famosi strumenti Masscan, Nmap, WhatWeb e unire servizi in uso, possibili vulnerabilità e relativi CVE in un unico report HTML.

Utilizzare questo tool solamente per la scansione di host propri o altrui con previo consenso.

---------------------------------------------

Data-flow del programma:

1: Masscan per ottenere le porte aperte.

2: Nmap sulle porte aperte per ottenere servizi e versioni.

3: Parsing dell'output Nmap.

4: WhatWeb per identificare tecnologie web.

5: Ricerca exploit su exploit-db e correlazione con CVE/NVD.

6: Generazione di un semplice report HTML finale.

---------------------------------------------

Installazione di ExploitDB:

Debian/Ubuntu: 

    sudo apt install exploitdb
macOS:

    brew install exploitdb 

---------------------------------------------

Per aggiornare il database di Searchsploit:

    searchsplot -u

---------------------------------------------

Permessi per Masscan in modo da non doverlo aprire come root:

    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which masscan)

---------------------------------------------

Per installare whatweb:

    sudo apt install whatweb

---------------------------------------------

Font figlet per il banner:

    https://www.figlet.org/examples.html


---------------------------------------------


La NVD_API_KEY è opzionale: senza chiave la ricerca sarà più lenta

Inserire la propria nel modulo config/apis.py

Per richiederla, visita questa pagina:

https://nvd.nist.gov/developers/request-an-api-key

---------------------------------------------

Stile di commenti usato:

Google-Style docstrings 

Ex.

    """
    Multiply two numbers.

    Args:
        a (int): First number.
        b (int): Second number.

    Returns:
        int: Product of a and b.
    """

---------------------------------------------

Come utilizzare il programma:

## Scarica database exploit-db
    sudo apt install exploitdb

## Aggiorna Searchsploit
    searchsploit -u

## Scarica Whatweb
    sudo apt install whatweb

## Clona la repo di questo programma
    git clone https://github.com/Mattpili/AutoScann3r.git

    cd AutoScann3r

## (Opzionale) Crea un virtual environment
    python3 -m venv .venv

    source .venv/bin/activate

## Installa le dipendenze richieste 
    pip install -r requirements.txt

## (Opzionale) Inserisci la tua chiave NVD
Inseriscila in config/apis.py

## Inserisci gli host da analizzare (come da esempio)
Inseriscili in core/targets/targets.csv

In questo formato:

Scanme;45.33.32.156

Scanme1;00.00.00.00

Scanme3;...

## Esegui il programma
    python app.py

## Consulta i report
Finita la scansione, visita la directory /reports






