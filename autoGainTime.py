#!/usr/bin/env python
from ina219 import INA219
from ina219 import DeviceRangeError
from gpiozero import LED
import time
import logging

# Configurazione del sensore INA219
SHUNT_OHMS = 0.1
MAX_EXPECTED_AMPS = 0.2

# Configurazione del LED sul pin GPIO 17
led = LED(17)
# Configurazione del logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
def read(ina):
    """Legge e stampa i valori di tensione, corrente, potenza e tensione sullo shunt del sensore INA219."""
    #print("Bus Voltage: %.3f V" % ina.voltage())
    try:
#        print("Bus Current: %.3f mA" % ina.current())
        print("Power: %.3f mW" % ina.power())
     #   print("Shunt Voltage: %.3f mV" % ina.shunt_voltage())
    except DeviceRangeError as e:
        # Corrente fuori dal range del dispositivo con il resistore shunt specificato
        print(e)

if __name__ == "__main__":
    # Configurazione e inizializzazione del sensore INA219
  #  ina = INA219(SHUNT_OHMS, MAX_EXPECTED_AMPS, busnum=1)
    ina = INA219(SHUNT_OHMS,busnum=1)
    ina.configure(ina.RANGE_16V,ina.ADC_9BIT)
    
    try:
        while True:
            led.on()  # Accendi il LED
            
            # Inizia la misurazione del tempo
            start_time = time.perf_counter()
            
            # Esegui la lettura del sensore
            read(ina)
            
            # Termina la misurazione del tempo
            end_time = time.perf_counter()

            # Calcola il tempo trascorso
            elapsed_time = end_time - start_time
            print(f"Tempo trascorso: {elapsed_time:.6f} secondi ({elapsed_time * 1_000_000:.0f} microsecondi)")
            
            # Mantieni il LED acceso per un secondo (facoltativo)
            # time.sleep(1)
    except KeyboardInterrupt:
        # Spegni il LED se il programma viene interrotto
        led.off()
