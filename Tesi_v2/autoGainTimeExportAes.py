#!/usr/bin/env python
from ina219 import INA219
from ina219 import DeviceRangeError
import time
import logging
import csv
from datetime import datetime
# Configurazione del sensore INA219
SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 0.2

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Nome del file CSV in cui salvare i dati
CSV_FILE = 'aes.csv'

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
    
    ina.configure(ina.RANGE_16V,ina.GAIN_8_320MV, ina.ADC_9BIT)
    
    # Aggiungi intestazioni al file CSV se è vuoto
    try:
        with open(CSV_FILE, mode='x', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Timestamp', 'Power (mW)'])
    except FileExistsError:
        # Il file esiste già, non fare nulla
        pass
    
   # try:
        while True:            
            # Inizia la misurazione del tempo
            start_time = time.perf_counter()
            
            # Esegui la lettura del sensore
            power = read(ina)
            
            # Termina la misurazione del tempo
            end_time = time.perf_counter()

            # Calcola il tempo trascorso
            elapsed_time = end_time - start_time
            # Salva i dati nel file CSV
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            if power is not None:
                write_to_csv(timestamp, power)
 #               print(f"Potenza salvata: {power} mW")

