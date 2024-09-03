# Funzione per calcolare il consumo della batteria
def calcola_consumo_batteria(capacita_batteria_mAh, potenza_per_pacco_mW, numero_pacchetti, durata_pacco_s):
    """
    Calcola il consumo della batteria in base alla potenza per pacchetto e al numero di pacchetti inviati.
    
    :param capacita_batteria_mAh: Capacità della batteria in milliampere-ora (mAh)
    :param potenza_per_pacco_mW: Potenza consumata per inviare un pacchetto in milliwatt (mW)
    :param numero_pacchetti: Numero di pacchetti inviati
    :param durata_pacco_s: Durata dell'invio di un pacchetto in secondi
    :return: Percentuale della batteria rimasta dopo l'invio dei pacchetti
    """
    
    # Converti la potenza in watt
    potenza_per_pacco_W = potenza_per_pacco_mW / 1000.0
    
    # Calcola l'energia consumata per pacchetto in wattora (Wh)
    energia_per_pacco_Wh = potenza_per_pacco_W * (durata_pacco_s / 3600.0)
    
    # Calcola l'energia totale consumata
    energia_totale_consumata_Wh = energia_per_pacco_Wh * numero_pacchetti
    
    # Capacità della batteria in wattora (Wh)
    capacita_batteria_Wh = capacita_batteria_mAh / 1000.0 * 3.7  # Supponendo una tensione della batteria di 3.7V
    
    # Calcola la percentuale di batteria rimasta
    batteria_rimasta_perc = 100 * (1 - energia_totale_consumata_Wh / capacita_batteria_Wh)
    
    return batteria_rimasta_perc

# Parametri di esempio
capacita_batteria_mAh = 3000  # Capacità della batteria in mAh
potenza_per_pacco_mW = 50     # Potenza consumata per pacchetto in mW
numero_pacchetti = 100         # Numero di pacchetti inviati
durata_pacco_s = 1            # Durata dell'invio di un pacchetto in secondi

# Calcola il consumo della batteria
batteria_rimasta_perc = calcola_consumo_batteria(capacita_batteria_mAh, potenza_per_pacco_mW, numero_pacchetti, durata_pacco_s)

print(f"La percentuale di batteria rimasta dopo l'invio di {numero_pacchetti} pacchetti è: {batteria_rimasta_perc:.2f}%")
