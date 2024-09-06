#!/usr/bin/env python
from ina219 import INA219
from ina219 import DeviceRangeError
from gpiozero import LED
import time
import logging
import csv

# Configurazione del sensore INA219
SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 0.2

# Configurazione del LED sul pin GPIO 17
led = LED(17)

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Nome del file CSV in cui salvare i dati
CSV_FILE = 'ckks.csv'

def read(ina):
    """Legge e stampa i valori di potenza del sensore INA219."""
    try:
        return ina.power()
    except DeviceRangeError as e:
        # Corrente fuori dal range del dispositivo con il resistore shunt specificato
        print(e)
        return None

def write_to_csv(timestamp, power):
    """Scrive i dati di potenza in un file CSV con un timestamp."""
    with open(CSV_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, power])

if __name__ == "__main__":
    # Configurazione e inizializzazione del sensore INA219
    ina = INA219(SHUNT_OHMS, busnum=1)
    ina.configure(ina.RANGE_16V, ina.ADC_9BIT)
    
    # Aggiungi intestazioni al file CSV se è vuoto
    try:
        with open(CSV_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Timestamp', 'Power (mW)'])
    except FileExistsError:
        # Il file esiste già, non fare nulla
        pass
    
    try:
        while True:
            led.on()  # Accendi il LED
            
            # Inizia la misurazione del tempo
            start_time = time.perf_counter()
            
            # Esegui la lettura del sensore
            power = read(ina)
            
            # Termina la misurazione del tempo
            end_time = time.perf_counter()

            # Calcola il tempo trascorso
            elapsed_time = end_time - start_time
            print(f"Tempo trascorso: {elapsed_time:.6f} secondi ({elapsed_time * 1_000_000:.0f} microsecondi)")

            # Salva i dati nel file CSV
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            if power is not None:
                write_to_csv(timestamp, power)
                print(f"Potenza salvata: {power} mW")

            # Mantieni il LED acceso per un secondo (facoltativo)
            # time.sleep(1)
            
            # Se si vuole fare una pausa tra le letture, decommentare la riga sottostante
            # time.sleep(1)

    except KeyboardInterrupt:
        # Spegni il LED se il programma viene interrotto
        led.off()
