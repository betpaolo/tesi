#!/usr/bin/env python
import argparse
from ina219 import INA219
from ina219 import DeviceRangeError
from gpiozero import LED
import time
import logging
import csv
from datetime import datetime

# Configurazione del sensore INA219
SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 0.2

# Configurazione del LED sul pin GPIO 17
led = LED(17)

# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read(ina):
    """Legge e stampa i valori di potenza del sensore INA219."""
    try:
        return ina.power()
    except DeviceRangeError as e:
        # Corrente fuori dal range del dispositivo con il resistore shunt specificato
        print(e)
        return None

def write_to_csv(csv_file, timestamp, power):
    """Scrive i dati di potenza in un file CSV con un timestamp."""
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, power])

if __name__ == "__main__":
    # Parsing degli argomenti della riga di comando
    parser = argparse.ArgumentParser(description="Leggi e registra la potenza dal sensore INA219")
    parser.add_argument('--output', type=str, default='ina219_data.csv', help="Nome del file CSV di output")
    args = parser.parse_args()

    csv_file = args.output

    # Configurazione e inizializzazione del sensore INA219
    ina = INA219(SHUNT_OHMS, busnum=1)
    ina.configure(ina.RANGE_16V, ina.ADC_9BIT)
    
    # Aggiungi intestazioni al file CSV se è vuoto
    try:
        with open(csv_file, mode='x', newline='') as file:
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

            # Salva i dati nel file CSV con timestamp a precisione microsecondo
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            if power is not None:
                write_to_csv(csv_file, timestamp, power)
                print(f"Potenza salvata: {power} mW")

            # Mantieni il LED acceso per un secondo (facoltativo)
            # time.sleep(1)
            
            # Se si vuole fare una pausa tra le letture, decommentare la riga sottostante
            # time.sleep(1)

    except KeyboardInterrupt:
        # Spegni il LED se il programma viene interrotto
        led.off()
