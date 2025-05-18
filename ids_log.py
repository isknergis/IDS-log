from scapy.all import sniff, TCP,IP
from datetime import datetime

#log dosyası yolu
LOG_DOSYA_YOLU ="port_taraması-log.txt"

def logla(mesaj):
	zaman_damgasi = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
	tam_mesaj = f"{zaman_damgasi} {mesaj}"
	print (tam_mesaj)
	
	#Dosyaya yaz
	with open(LOG_DOSYA_YOLU, "a") as dosya:
		dosya.write(tam_mesaj +"\n")
		
def analiz_et(paket):
    if TCP in paket and IP in paket:
        tcp_katmani = paket[TCP]
        ip_katmani = paket[IP]

        # Sadece SYN bayrağı varsa
        if tcp_katmani.flags == "S":
            kaynak_ip = ip_katmani.src
            hedef_ip = ip_katmani.dst
            hedef_port = tcp_katmani.dport

            mesaj = f"POTANSİYEL PORT TARAMASI : {kaynak_ip} -> {hedef_ip}:{hedef_port}"
            logla(mesaj)
		
if __name__=="__main__":
	print("ISD başlatıldı....\n")
	sniff(filter="tcp", prn=analiz_et, store=0)
