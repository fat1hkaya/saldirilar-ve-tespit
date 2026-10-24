# Yol Haritası — Kurumsal SOC için en önemli 100 saldırı

Bu liste, kurumsal bir SOC'ta (Windows/Active Directory ağırlıklı ağ, Microsoft 365/Entra ID, internete açık web uygulamaları ve sınır cihazları, hibrit bulut) **en sık alarm üreten ve en büyük hasara yol açan** saldırılardan seçildi. Numara aynı zamanda çalışma sırasıdır: bölümler bir saldırganın kurum içinde izlediği yolu takip eder — ilk erişim → kimlik bilgisi → Active Directory → yürütme ve gizlenme → kalıcılık → yanal hareket ve C2 → sızdırma ve etki; ardından ağ ve bulut.

**Öncelik:** 🔴 Kritik (ihlal ve fidye zincirlerinde neredeyse her zaman görülür) · 🟠 Yüksek · 🟡 Orta  
✅ = tamamlandı

| Bölüm | Klasör | Aralık | Adet |
|---|---|---|---|
| 1. Web uygulamaları ve sınır cihazları | `01-web` | 001–010 | 10 |
| 2. Phishing ve sosyal mühendislik | `02-phishing` | 011–020 | 10 |
| 3. Kimlik bilgisi saldırıları | `03-kimlik` | 021–030 | 10 |
| 4. Active Directory | `04-active-directory` | 031–044 | 14 |
| 5. Yürütme ve savunma atlatma | `05-yurutme-atlatma` | 045–055 | 11 |
| 6. Kalıcılık ve yetki yükseltme | `06-kalicilik-yetki` | 056–065 | 10 |
| 7. Yanal hareket ve C2 | `07-yanal-hareket-c2` | 066–075 | 10 |
| 8. Sızdırma, ransomware ve etki | `08-sizdirma-etki` | 076–084 | 9 |
| 9. Ağ saldırıları ve DDoS | `09-ag-ddos` | 085–090 | 6 |
| 10. Bulut, SaaS, tedarik zinciri ve AI | `10-bulut-tedarik` | 091–100 | 10 |

---

## 1. Web uygulamaları ve sınır cihazları (001–010)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 001 ✅ | SQL Injection | T1190 | 🔴 | MOVEit, FortiWeb, Drupal: internete açık uygulamadan doğrudan veri ihlali |
| 002 | Cross-Site Scripting (XSS) | T1190, T1539 | 🟠 | Oturum çalma, yönetici paneli ele geçirme; WAF alarmlarının büyük kısmı |
| 003 | OS Command Injection | T1190, T1059 | 🔴 | Web'den doğrudan sunucuda komut; sınır cihazı CVE'lerinin çoğu bu sınıfta |
| 004 | Path Traversal ve LFI/RFI | T1190, T1083 | 🟠 | Yapılandırma ve parola dosyası okuma; sık taranan zafiyet |
| 005 | Dosya yükleme ve web shell | T1505.003 | 🔴 | Web saldırılarının kalıcılık adımı; IIS/Apache süreçlerinden kabuk |
| 006 | SSRF ve bulut metadata erişimi | T1190, T1552.005 | 🟠 | İç ağa ve bulut kimlik bilgilerine (IMDS) köprü |
| 007 | Log4Shell ve JNDI injection | T1190 | 🟠 | Kurumsal Java uygulamalarında hâlâ sömürülen kritik zafiyet sınıfı |
| 008 | VPN ve firewall (sınır cihazı) sömürüsü | T1190, T1133 | 🔴 | Fortinet, Ivanti, Citrix, Palo Alto: 2024–2026 ihlallerinin bir numaralı giriş noktası |
| 009 | Exchange ve SharePoint sunucu saldırıları | T1190, T1505.003 | 🔴 | ProxyShell ve ToolShell türü zincirler; kurum içi sunucuda kalıcılık |
| 010 | IDOR/BOLA ve API kötüye kullanımı | T1190 | 🟠 | Kimlik doğrulaması olan ama yetkilendirmesi bozuk API'lerden toplu veri çekme |

## 2. Phishing ve sosyal mühendislik (011–020)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 011 | Phishing e-posta analizi (başlık, SPF/DKIM/DMARC) | T1566 | 🔴 | L1 analistin günlük işinin en büyük kısmı; kullanıcı bildirimleri |
| 012 | Zararlı ekler (Office makro, LNK, ISO, OneNote) | T1566.001, T1204.002 | 🔴 | Loader ve ransomware zincirlerinin klasik başlangıcı |
| 013 | Zararlı linkler ve HTML smuggling | T1566.002, T1027.006 | 🔴 | E-posta ağ geçidini atlatan modern teslim yöntemi |
| 014 | Business Email Compromise (BEC) | T1656, T1564.008 | 🔴 | Maddi kaybı en yüksek saldırı türü; sahte fatura, IBAN değişikliği |
| 015 | AiTM phishing ve oturum çalma (Evilginx) | T1557, T1539 | 🔴 | MFA'yı atlatan M365 hesap ele geçirmelerinin ana yöntemi |
| 016 | MFA fatigue / push bombing | T1621 | 🟠 | Ele geçirilmiş parola sonrası MFA'yı kullanıcıya onaylatma |
| 017 | OAuth consent ve device code phishing | T1528, T1566.002 | 🟠 | Parola gerektirmeyen, kalıcı token veren bulut saldırısı |
| 018 | QR kod phishing (quishing) | T1566 | 🟡 | E-posta filtrelerini atlatıp mobil cihaza kayıyor |
| 019 | Vishing ve help desk sosyal mühendisliği | T1566.004, T1656 | 🟠 | Scattered Spider tarzı parola/MFA sıfırlatma; büyük kurumsal ihlaller |
| 020 | ClickFix, sahte CAPTCHA, SEO poisoning ve malvertising | T1204.004, T1608.006 | 🔴 | Kullanıcıya komut yapıştırtan, 2025–2026'nın en hızlı büyüyen teslim yöntemi |

## 3. Kimlik bilgisi saldırıları (021–030)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 021 | Brute force (RDP, SSH, VPN, web login) | T1110.001 | 🔴 | En sık tetiklenen alarm; eşik ve korelasyon tasarımının temeli |
| 022 | Password spraying (AD ve Entra ID) | T1110.003 | 🔴 | Hesap kilitlemeye takılmadan kurum genelinde parola denemesi |
| 023 | Credential stuffing | T1110.004 | 🟠 | Sızmış parola listeleriyle VPN ve portal hesaplarına giriş |
| 024 | LSASS bellek dökümü | T1003.001 | 🔴 | Windows'ta kimlik bilgisi hırsızlığının merkezi; yanal hareketin yakıtı |
| 025 | Infostealer ve tarayıcı parola/çerez hırsızlığı | T1555.003, T1539 | 🔴 | Lumma, RedLine: kurumsal SaaS hesaplarına giriş biletleri |
| 026 | Pass-the-Hash | T1550.002 | 🔴 | Parola bilmeden NTLM hash ile kimlik doğrulama |
| 027 | Pass-the-Ticket ve Overpass-the-Hash | T1550.003 | 🟠 | Kerberos biletleriyle yanal hareket |
| 028 | LLMNR/NBT-NS/mDNS poisoning | T1557.001 | 🟠 | İç ağda pasif hash toplama; pentest ve saldırganların ilk adımı |
| 029 | NTLM relay | T1557.001 | 🔴 | Relay ile sunucu ve sertifika servisi ele geçirme |
| 030 | Token ve çerez çalma (pass-the-cookie) | T1539, T1550.004 | 🟠 | MFA sonrası oturumun başka cihazda kullanılması |

## 4. Active Directory (031–044)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 031 | AD keşfi (BloodHound/SharpHound, AdFind) | T1087.002, T1069.002 | 🔴 | Ransomware öncesi neredeyse her vakada görülen keşif |
| 032 | Kerberoasting | T1558.003 | 🔴 | Servis hesabı parolalarını offline kırma; tespiti öğrenilmesi gereken klasik |
| 033 | AS-REP Roasting | T1558.004 | 🟠 | Ön kimlik doğrulaması kapalı hesaplar |
| 034 | DCSync | T1003.006 | 🔴 | Domain'in tüm hash'lerini replikasyonla çekme |
| 035 | NTDS.dit çalma | T1003.003 | 🔴 | Shadow copy ile domain veritabanını kopyalama |
| 036 | Golden Ticket | T1558.001 | 🔴 | krbtgt ile sınırsız ve kalıcı domain erişimi |
| 037 | Silver Ticket | T1558.002 | 🟠 | Tek servise sahte bilet; DC loglarında görünmez |
| 038 | AD Certificate Services (ADCS) kötüye kullanımı | T1649 | 🔴 | ESC1–ESC8: sertifika ile domain admin; çoğu kurumda açık |
| 039 | Kerberos delegation kötüye kullanımı (unconstrained, constrained, RBCD) | T1558, T1134 | 🟠 | Yanlış delegasyon ayarından yetki yükseltme |
| 040 | Shadow Credentials | T1098 | 🟡 | msDS-KeyCredentialLink ile parola değiştirmeden hesap ele geçirme |
| 041 | ACL ve GPO kötüye kullanımı | T1484.001, T1222.001 | 🟠 | Yanlış yetkilerden domain admin'e; GPO ile toplu yazılım dağıtımı |
| 042 | Kimlik doğrulama zorlama (PetitPotam, PrinterBug) | T1187 | 🟠 | DC'yi kimlik doğrulamaya zorlayıp relay'e bağlama |
| 043 | Kritik AD zafiyetleri (Zerologon, noPac, PrintNightmare) | T1210, T1068 | 🟠 | Yaması eksik DC'de dakikalar içinde domain ele geçirme |
| 044 | AD kalıcılığı (AdminSDHolder, DCShadow, Skeleton Key) | T1098, T1207, T1556.001 | 🟠 | Temizlikten sonra geri dönüş kapıları |

## 5. Yürütme ve savunma atlatma (045–055)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 045 | Zararlı PowerShell kullanımı | T1059.001 | 🔴 | Windows saldırılarının ortak dili; Script Block Logging analizi |
| 046 | LOLBins (certutil, mshta, rundll32, regsvr32) | T1218 | 🔴 | İmzalı Windows araçlarıyla zararlı yürütme |
| 047 | WMI ile yürütme | T1047 | 🟠 | Yerel ve uzak komut çalıştırma, keşif |
| 048 | Process injection ve process hollowing | T1055 | 🟠 | Meşru süreç içinde gizlenme; EDR telemetrisi okuma |
| 049 | DLL sideloading ve DLL hijacking | T1574.001 | 🟠 | İmzalı uygulama ile zararlı DLL yükleme; APT ve loader favorisi |
| 050 | AMSI ve ETW atlatma | T1562.001, T1562.006 | 🟠 | Güvenlik telemetrisini körleştirme |
| 051 | EDR/AV devre dışı bırakma ve BYOVD | T1562.001, T1068 | 🔴 | Ransomware öncesi standart adım; zafiyetli sürücü yükleme |
| 052 | Log silme ve anti-forensics | T1070.001, T1070.006 | 🔴 | Event ID 1102/104: tek başına yüksek güvenilirlikli alarm |
| 053 | Masquerading ve parent PID spoofing | T1036, T1134.004 | 🟡 | Sahte süreç adı ve ebeveyn ile analisti yanıltma |
| 054 | UAC bypass | T1548.002 | 🟡 | Yerel yönetici hesabında yükseltilmiş yetki |
| 055 | Token impersonation (Potato ailesi) | T1134.001 | 🟠 | Servis hesabından SYSTEM'e; web shell sonrası klasik adım |

## 6. Kalıcılık ve yetki yükseltme (056–065)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 056 | Zamanlanmış görev (scheduled task) kalıcılığı | T1053.005 | 🔴 | En yaygın Windows kalıcılık yöntemi |
| 057 | Registry Run key ve Startup klasörü | T1547.001 | 🔴 | Commodity malware'in standart kalıcılığı |
| 058 | Zararlı servis oluşturma | T1543.003 | 🔴 | PsExec ve ransomware dağıtımında Event ID 7045 |
| 059 | WMI event subscription kalıcılığı | T1546.003 | 🟡 | Dosyasız, gözden kaçan kalıcılık |
| 060 | Windows yerel yetki yükseltme (zayıf servis izinleri, unquoted path) | T1574, T1068 | 🟠 | Kullanıcıdan SYSTEM'e |
| 061 | Linux yetki yükseltme (SUID, sudo, capabilities, kernel) | T1548.001, T1068 | 🟠 | Web sunucusu ele geçirildikten sonra root |
| 062 | Linux kalıcılığı (cron, systemd, SSH anahtarları) | T1053.003, T1543.002, T1098.004 | 🟠 | Sunucularda uzun süreli erişim |
| 063 | Yetkisiz hesap oluşturma ve gruba ekleme | T1136, T1098 | 🔴 | Event ID 4720/4728/4732: domain admin grubuna ekleme |
| 064 | RMM aracı kötüye kullanımı (AnyDesk, ScreenConnect) | T1219 | 🔴 | Meşru uzak erişim araçlarıyla C2 ve kalıcılık |
| 065 | COM hijacking, IFEO ve erişilebilirlik backdoor'ları | T1546.015, T1546.012, T1546.008 | 🟡 | Sticky keys ve benzeri gizli giriş kapıları |

## 7. Yanal hareket ve C2 (066–075)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 066 | PsExec ve SMB ile yanal hareket | T1021.002, T1569.002 | 🔴 | Ransomware dağıtımının ana aracı |
| 067 | WinRM ve PowerShell Remoting | T1021.006 | 🟠 | Yönetici aracı görünümünde yanal hareket |
| 068 | RDP ile yanal hareket ve oturum ele geçirme | T1021.001, T1563.002 | 🔴 | En yaygın hands-on-keyboard yanal hareket yöntemi |
| 069 | DCOM ile uzaktan yürütme | T1021.003 | 🟡 | Daha az izlenen yanal hareket yolu |
| 070 | Cobalt Strike tespiti | T1071.001, T1055 | 🔴 | Ransomware ve APT'lerin en yaygın C2 aracı |
| 071 | Modern C2 çerçeveleri (Sliver, Havoc, Mythic) | T1071 | 🟠 | Cobalt Strike'ın yerini alan açık kaynak C2'ler |
| 072 | C2 beaconing tespiti (ağ) | T1071, T1573 | 🔴 | Zamanlama ve hacim analiziyle imzasız C2 avcılığı |
| 073 | DNS tunneling | T1071.004, T1572 | 🟠 | DNS üzerinden C2 ve veri sızdırma |
| 074 | Tünelleme ve pivoting (ngrok, chisel, Cloudflare Tunnel, SSH) | T1572, T1090 | 🟠 | Firewall'u içeriden delen erişim |
| 075 | Meşru servisler üzerinden C2 (Telegram, Discord, bulut API'leri) | T1102 | 🟠 | İzinli domainlere gizlenmiş C2 trafiği |

## 8. Sızdırma, ransomware ve etki (076–084)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 076 | Bulut depolamaya veri sızdırma (rclone, MEGA) | T1567.002 | 🔴 | Double extortion'ın sızdırma adımı |
| 077 | Ransomware yaşam döngüsü (uçtan uca) | T1486 | 🔴 | Kurumların en büyük operasyonel riski |
| 078 | Shadow copy silme ve yedek imhası | T1490 | 🔴 | Şifrelemeden dakikalar önce görülen son uyarı |
| 079 | Ransomware öncü göstergeleri (hands-on-keyboard aktivitesi) | T1046, T1018 | 🔴 | Şifrelemeden günler önce yakalama şansı |
| 080 | ESXi ve hypervisor ransomware | T1486 | 🔴 | Tek seferde yüzlerce sanal makineyi şifreleme |
| 081 | Wiper saldırıları | T1485, T1561 | 🟠 | Geri dönüşsüz veri imhası |
| 082 | İçeriden tehdit ve veri hırsızlığı | T1052.001, T1567 | 🟠 | USB, kişisel bulut ve e-posta ile veri çıkarma |
| 083 | Loader zararlıları (QakBot, IcedID, Latrodectus) | T1204, T1105 | 🔴 | Phishing'den ransomware'e geçiş köprüsü |
| 084 | RAT'lar (AsyncRAT, Remcos) | T1071, T1105 | 🟠 | Commodity uzaktan erişim truva atları |

## 9. Ağ saldırıları ve DDoS (085–090)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 085 | Port tarama ve ağ keşfi | T1046 | 🔴 | Dış tarayıcı gürültüsü ile içeriden tarama ayrımı |
| 086 | ARP spoofing ve MITM | T1557.002 | 🟡 | İç ağda trafik dinleme ve değiştirme |
| 087 | DNS saldırıları (hijack, poisoning, sahte domainler) | T1584.002, T1557 | 🟠 | Domain ele geçirme ve marka taklidi |
| 088 | Volumetrik DDoS (SYN, UDP, amplification) | T1498 | 🟠 | Bankacılık ve kamu için sürekli tehdit |
| 089 | Uygulama katmanı DDoS (HTTP flood, HTTP/2 Rapid Reset) | T1499 | 🟠 | WAF ve CDN arkasında bile hizmet kesintisi |
| 090 | Wi-Fi saldırıları (Evil Twin, rogue AP) | T1557.004 | 🟡 | Ofis ve misafir ağlarında kimlik bilgisi toplama |

## 10. Bulut, SaaS, tedarik zinciri ve AI (091–100)

| # | Saldırı | MITRE ATT&CK | Öncelik | Kurumsal SOC açısından neden önemli |
|---|---|---|---|---|
| 091 | M365 / Entra ID hesap ele geçirme ve posta kutusu kuralları | T1078.004, T1564.008 | 🔴 | BEC'in bulut tarafı; şüpheli giriş ve gelen kutusu kuralı |
| 092 | Entra ID yetki yükseltme ve kalıcılık (uygulama kaydı, service principal) | T1098.001, T1098.003 | 🟠 | Bulut kimliğinde gizli kapılar |
| 093 | AWS IAM anahtar sızıntısı ve yetki yükseltme | T1078.004, T1552 | 🟠 | Sızmış access key ile bulut hesabını ele geçirme |
| 094 | Bulut depolama ifşası ve veri hırsızlığı (S3, Blob) | T1530 | 🟠 | Yanlış yapılandırma kaynaklı toplu veri sızıntısı |
| 095 | Bulut loglarını kapatma ve savunma atlatma | T1562.008 | 🟡 | CloudTrail ve Audit log tahribatı |
| 096 | Kubernetes ve container saldırıları | T1610, T1611 | 🟡 | Container kaçışı ve cluster ele geçirme |
| 097 | Zararlı paketler ve dependency confusion | T1195.001 | 🟠 | npm/PyPI üzerinden geliştirici makinelerine sızma |
| 098 | Ele geçirilmiş yazılım güncellemesi (SolarWinds, 3CX) | T1195.002 | 🟠 | Güvenilen yazılım üzerinden binlerce kuruma erişim |
| 099 | CI/CD ve GitHub Actions sırlarının çalınması | T1552 | 🟡 | Pipeline sırlarıyla üretim ortamına erişim |
| 100 | Prompt injection ve AI agent kötüye kullanımı | MITRE ATLAS AML.T0051 | 🟡 | Kurumsal AI asistanları ve ajanlarıyla veri sızdırma |

---

**101 ve sonrası:** İlk 100 tamamlandıktan sonra daha niş konular (OT/ICS, mobil, IoT, ileri web zafiyetleri, ileri AD/bulut teknikleri) ayrı bir liste olarak eklenecek.
