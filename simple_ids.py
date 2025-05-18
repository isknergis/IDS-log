from scapy.all import sniff, TCP, IP
from datetime import datetime

# Şüpheli bağlantıları kontrol eden fonksiyon
def tespit_et(paket):
#Bu fonksiyon, gelen her paketi kontrol edecek. Her paket geldiğinde bu fonksiyon çağrılacak.
    if paket.haslayer(TCP) and paket.haslayer(IP):
    #Eğer gelen paket hem TCP hem IP katmanına sahipse kontrol edilecek. (Yani TCP bağlantısı taşıyan bir IP paketi)
        tcp_layer = paket.getlayer(TCP)
        ip_layer = paket.getlayer(IP)
        #Gelen paketin TCP ve IP bilgilerini ayrı değişkenlere alıyoruz. Böylece kolayca analiz edeceğiz.

        # SYN var ama ACK yoksa —> Port tarama olabilir
        if tcp_layer.flags == "S":
        #TCP flags değeri sadece "S" (SYN) ise —> Bu paket SYN taraması olabilir.Çünkü normal bir bağlantıda SYN'den sonra ACK de gelir. Ama burada sadece SYN var.
            zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            #Şüpheli hareketin zamanını kaydediyoruz. Böylece loglarda hangi saatte gerçekleştiğini görürüz.
            print(f"[{zaman}] POTANSİYEL PORT TARAMASI: {ip_layer.src} → {ip_layer.dst}:{tcp_layer.dport}")

# Trafiği dinle (yalnızca TCP paketler)
print("IDS başlatıldı... (Çıkmak için Ctrl+C)")
sniff(filter="tcp", prn=tespit_et, store=False)
