# #003 — OS Command Injection (İşletim Sistemi Komut Enjeksiyonu)

> Uygulamanın kullanıcıdan aldığı veriyi bir **kabuk (shell) komutunun içine** koyması ve kabuğun bu veriyi metin değil yeni komut olarak yorumlaması; sonuç, web sunucusunun veya cihazın yetkisiyle — sınır cihazlarında çoğunlukla **root** — uzaktan kod çalıştırmadır. PAN-OS GlobalProtect (CVE-2024-3400), Ivanti Connect Secure (CVE-2024-21887), Cisco ISE (CVE-2025-20281), FortiSandbox (CVE-2026-39808) ve NetScaler (CVE-2026-88771) olayları gösterdi ki son yılların en ağır sınır cihazı ihlallerinin çoğu bu tek hata sınıfından doğuyor; CISA ve FBI 2024'te bu sınıfı "ortadan kaldırılması gereken" kusur ilan etti.

## Özet kartı

| Alan | Değer |
|---|---|
| Kategori | Web uygulamaları ve sınır cihazları (Web #3) — sunucu tarafı enjeksiyon |
| OWASP Top 10 (2021) | A03:2021 – Injection |
| CWE | CWE-78 (OS Command Injection), CWE-77 (Command Injection), CWE-88 (Argument Injection), CWE-20 (yetersiz girdi doğrulama) |
| CAPEC | CAPEC-88 (OS Command Injection), CAPEC-248 (Command Injection), CAPEC-6 (Argument Injection) |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application · T1059.004 Unix Shell · T1059.003 Windows Command Shell · T1059.001 PowerShell · T1105 Ingress Tool Transfer · T1505.003 Web Shell · T1033/T1082 Keşif · T1053.003 Cron · T1090 Proxy (tünel) |
| Etki (CIA) | **C:** yapılandırma, parola hash'leri, VPN oturumları, AD kimlik bilgileri · **I:** sistem/cihaz üzerinde tam kontrol, kalıcı arka kapı · **A:** servis durdurma, fidye yazılımına geçiş |
| Tipik CVSS 3.1 | 8.8 – 10.0 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` kimlik doğrulamasız; sınır cihazında `S:C` ile 10.0) |
| Saldırgan seviyesi | Otomatik (commix, Nuclei şablonları, botnet'ler) → İleri (0-day zincirleri, ikinci dereceden/kör enjeksiyon, devlet destekli gruplar) |
| SOC önceliği | Deneme (imzalı istek, 403/400): **Düşük–Orta** · Web süreci altında kabuk / keşif komutu / dışarıdan araç indirme / sınır cihazından olağan dışı çıkış trafiği: **Kritik** |
| Wazuh kural bloğu | 100300 – 100399 |

## 30 saniyede SOC özeti

1. **Ne arıyorum?** URL/gövdede kabuk ayraçları (`;` `|` `&&` `` ` `` `$(`) ile birlikte komut adları (`id`, `whoami`, `uname`, `curl`, `wget`, `powershell`, `cmd`), zaman gecikmesi ve dış DNS geri araması (OAST) izleri; **asıl önemlisi uç noktada:** web sunucusu sürecinin (`www-data`, `w3wp.exe`, `httpd`, `java`, `node`) çocuk süreci olarak `sh/bash/cmd/powershell`.
2. **Deneme mi başarı mı?** 403/400 dönen imzalı istekler denemedir. **Başarı belirtileri:** web/servis kullanıcısının `execve` ile kabuk ve keşif komutu çalıştırması (auditd/Sysmon), web kökünde yeni dosya, sunucudan/cihazdan beklenmeyen dış bağlantı (araç indirme, ters kabuk), yeni cron/servis, sınır cihazından iç ağa SMB/WinRM.
3. **İlk aksiyon?** Deneme → IP'yi engelle, ürün sürümünü KEV ile karşılaştır, kapat. Başarı → sunucuyu/cihazı ağdan izole et (sınır cihazında yönetim arayüzünü kapat, mümkünse yedeğe geç), bellek ve disk delilini al, cihazın tuttuğu tüm kimlik bilgilerini ihlal edilmiş say, L2/IR'a eskale et.

## İçindekiler

1. [Teori: komut enjeksiyonu nasıl çalışır?](#01--teori-komut-enjeksiyonu-nasıl-çalışır)
2. [Saldırı akışı ve her aşamanın izi](#02--saldırı-akışı-ve-her-aşamanın-izi)
3. [Tespit: istek, süreç, ağ ve cihaz katmanları](#03--tespit-istek-süreç-ağ-ve-cihaz-katmanları)
4. [Önleme, sertleştirme ve olay müdahalesi](#04--önleme-sertleştirme-ve-olay-müdahalesi)
5. [Pratik: odalar, lab ve kaynaklar](#05--pratik-odalar-lab-ve-kaynaklar)

**Bu klasördeki diğer dosyalar (kopyala-yapıştır için):**

| Dosya | İçerik |
|---|---|
| [`splunk.spl`](splunk.spl) | 12 SPL sorgusu, numaralı bölümler halinde |
| [`wazuh.xml`](wazuh.xml) | Özel kurallar (100300–100399) + aktif yanıt + agent ayarları (auditd, Sysmon) |
| [`ornek.log`](ornek.log) | Access, ModSecurity, Linux auditd ve Windows Sysmon test satırları |

## 01 — Teori: komut enjeksiyonu nasıl çalışır?

### 1.1 Kök neden: veri, kabuğun söz dizimine karışır

Birçok uygulama işini kendisi yapmak yerine bir işletim sistemi aracını çağırır: ping/traceroute testi yapan ağ cihazı paneli, dosya dönüştüren servis, yedek alan betik, sertifika üreten yönetim arayüzü. Geliştirici bu çağrıyı **tek bir metin** olarak kurup kabuğa verirse (`system()`, `exec()`, `shell_exec()`, `os.system()`, `subprocess(..., shell=True)`, `Runtime.exec("sh -c ...")`, `child_process.exec()`), kabuk metni kendi kurallarıyla ayrıştırır. Kullanıcı verisi kabuğun **özel karakterlerini** taşıyorsa, verinin sınırı aşılır ve kabuk yeni bir komut başlatır.

SQLi (#001) ile aynı hatadır — **kod ile verinin aynı kanalda taşınması** — ama yorumlayıcı veritabanı değil işletim sistemi kabuğudur. Bu yüzden etki doğrudan sunucuda/cihazda kod çalıştırmadır; veritabanı yetkisi gibi bir ara katman yoktur.

#### Kabuk hangi karakterlere "yapı" der?

| Sınıf | Örnek karakterler | Kabuktaki anlamı | Tespit notu |
|---|---|---|---|
| Komut ayracı | `;` `\n` (`%0a`) `&` | Ardışık / arka planda komut | URL'de `%3b`, `%0a`, `%26` kodlu hâlleri |
| Koşullu zincir | `&&` `\|\|` | Önceki komuta bağlı çalıştırma | `%26%26`, `%7c%7c` |
| Boru | `\|` | Çıktıyı başka komuta aktarma | `%7c` |
| Komut ikamesi | `` `...` `` `$(...)` | İç komutun çıktısını dışa yerleştirme | `%60`, `%24%28` — **kör enjeksiyonun favorisi** |
| Yönlendirme | `>` `<` `>>` | Çıktıyı dosyaya yazma (web köküne!) | Web dizininde yeni dosya ile korele et |
| Değişken / genişletme | `$VAR` `${IFS}` `*` `?` `~` | Boşluk/karakter kısıtını aşma | `${IFS}` gibi kalıplar meşru girdide neredeyse hiç yoktur |
| Windows `cmd.exe` | `&` `\|` `^` `%VAR%` | Ayraç, kaçış ve değişken | `^` kaçışı ve `%COMSPEC%` benzeri ifadeler |

**Argüman enjeksiyonu (CWE-88)** ayrı bir alt sınıftır: kabuk hiç devreye girmese bile kullanıcı verisi aracın **seçeneği** olarak yorumlanabilir (`-` ile başlayan değer). Örneğin bir arşiv, `git`, `curl` veya `find` çağrısında bir seçenek dosya yazdırabilir ya da başka bir program çalıştırabilir. Bu yüzden "kabuk kullanmıyorum" tek başına yeterli değildir.

### 1.2 Saldırı yüzeyi: girdi nereden gelir?

| Kaynak | Örnek | Neden gözden kaçar |
|---|---|---|
| URL/form parametresi | `?host=`, `?ip=`, `?file=`, `?cmd=` | En klasik yüzey; tarayıcıların ilk denediği yer |
| JSON/XML gövdesi, REST API | Yönetim API'lerinde cihaz adı, tünel adı, sertifika alanı | Erişim log'unda gövde görünmez |
| HTTP başlıkları ve çerezler | `User-Agent`, özel başlıklar, **oturum çerezi** | CVE-2024-3400'te saldırgan verisi oturum kimliği alanından dosya yoluna taşındı |
| Dosya adı ve meta veri | Yüklenen dosyanın adı, EXIF, arşiv içi yol | Dönüştürücü/antivirüs/önizleme araçlarına geçer |
| **Log ve kuyruk kayıtları (ikinci dereceden)** | Kullanıcı adı log'a yazılır, sonra bir bakım betiği o satırı kabuğa verir | İstek anında hiçbir şey olmaz; çalışma saatler sonra, **başka bir süreçte** |
| Ağ cihazı tanılama ekranları | Ping, traceroute, DNS sorgusu, NTP testi | Gömülü cihazlarda root ile çalışır, EDR yoktur |
| CI/CD ve otomasyon | Branch adı, commit mesajı, iş akışı parametresi | Pipeline betikleri değişkeni doğrudan kabuğa verir |
| AI/LLM araç çağrıları | Modelin ürettiği komut veya argüman bir araca iletilir | Girdi dolaylıdır; komut istem enjeksiyonuyla şekillenir (bkz. #100 serisi) |

### 1.3 Komut enjeksiyonu türleri — sonuç saldırgana nasıl döner?

| Tür | Mekanizma (kavramsal) | Savunucunun gördüğü iz |
|---|---|---|
| **Sonuç dönen (in-band)** | Komut çıktısı HTTP yanıtına yansır | Normalden **büyük yanıt boyutu**, 200; erişim log'unda imzalı istek |
| **Kör – zaman tabanlı** | Çıktı görünmez; gecikme komutuyla doğruluk sorgulanır | İstek süresi (`%D`, `time-taken`) sistematik olarak artar; aynı parametrede tekrarlı denemeler |
| **Kör – bant dışı (OAST)** | Komut dışarıya DNS/HTTP isteği yaptırır | Sunucudan/cihazdan **dış DNS sorgusu** — herkese açık geri arama servislerine veya rastgele alt alan adlarına |
| **Kör – dosya yazma** | Çıktı web köküne yazılır, sonra okunur | Web kökünde yeni `.txt`/`.css`/`.js` dosyası, ardından o dosyaya GET (CVE-2024-3400 kalıbı) |
| **İkinci dereceden (stored)** | Veri önce kaydedilir (log, DB, kuyruk), başka bir süreç sonra kabuğa verir | İstek ile çalışma arasında zaman farkı; çalıştıran süreç web sunucusu değil **bakım/cron betiği** (CVE-2026-88771 kalıbı) |
| **Argüman enjeksiyonu** | Veri seçenek olarak yorumlanır | Komut satırında beklenmeyen seçenekler (`-o`, `--output`, `-exec`); kabuk süreci olmayabilir |

### 1.4 Ortam ve ürün farkları

| Ortam | Neden riskli | Savunma notu |
|---|---|---|
| **VPN / firewall / ADC (sınır cihazları)** | İnternete açık, yönetim/portal servisleri genelde **root**; EDR kurulamaz; kurumun tüm kimlik doğrulaması bu cihazdan geçer | KEV takibi + saatler içinde yama; yönetim arayüzünü internete kapat; cihaz log'larını ve **cihazdan çıkan trafiği** SIEM'e al |
| Linux web sunucusu (PHP, Python, Node) | `www-data` kabuk açabilir, `/tmp` yazılabilir, `curl/wget` kurulu | auditd `execve` + web kullanıcısı için çıkış kısıtı |
| Windows/IIS (.NET), Java (Tomcat) | `w3wp.exe`/`java.exe` → `cmd.exe`/`powershell.exe` | Sysmon EID 1, ASR kuralları, AppLocker/WDAC |
| Gömülü cihazlar (router, NAS, kamera, IoT) | BusyBox kabuk, yama zor, kimlik doğrulamasız tanılama sayfaları | Botnet hedefi (Mirai türevleri); ağ segmentasyonu, yönetim VLAN'ı |
| Konteyner / Kubernetes | Konteyner içinde root, servis hesabı token'ı, bulut meta veri servisi | Salt-okunur dosya sistemi, `runAsNonRoot`, Falco/Tetragon süreç kuralları |
| CI/CD ve iş akışı motorları | Gizli anahtarlar ve üretim erişimi aynı ortamda | Değişkenleri ortam değişkeni olarak geçir, `script` içine gömme |

### 1.5 Neden hâlâ bu kadar yaygın?

- **Kısayol cazibesi:** Bir aracı kabuk üzerinden tek satırla çağırmak, kütüphane API'si kullanmaktan kolaydır.
- **Gömülü ve eski kod tabanları:** Ağ cihazlarının yönetim katmanları yıllardır büyüyen CGI/Perl/Python betikleridir; CISA'nın 2024 uyarısı tam olarak bu ürünleri hedef aldı.
- **Dolaylı veri akışı:** Veri log'a, yapılandırmaya veya kuyruğa yazılıp başka bir betikte kabuğa ulaşır; kod incelemesinde kaynak ile hedef farklı dosyalardadır.
- **"Sadece yöneticiler kullanıyor" varsayımı:** Kimlik doğrulama atlatması (auth bypass) ile birleşince yönetici arayüzündeki komut enjeksiyonu kimlik doğrulamasız RCE olur (Ivanti CVE-2023-46805 + CVE-2024-21887 zinciri bunun örneğidir).
- **Ödül büyük:** Sınır cihazında root = VPN oturumları, parola hash'leri, ağın içine köprü. Bu yüzden devlet destekli gruplar ve fidye operatörleri bu sınıfa sürekli 0-day yatırımı yapar.

---

## 02 — Saldırı akışı ve her aşamanın izi

> Bu bölüm saldırıyı **savunucu gözüyle** anlatır: saldırgan her aşamada neyi hedefler ve geride hangi iz kalır. Uygulamalı pratik için [§5](#05--pratik-odalar-lab-ve-kaynaklar)'teki yasal lab'ları kullan.

### 2.1 Aşamalar ve MITRE ATT&CK eşleşmesi

| # | Aşama | Saldırganın hedefi | ATT&CK | Bıraktığı iz | Tespit fırsatı |
|---|---|---|---|---|---|
| 1 | Keşif ve sürüm tespiti | Savunmasız ürün/sürümü bulmak (internet çapında tarama) | T1595.002, T1592 | Bilinen yollara (`/global-protect/`, `/dana-na/`, `/api/`) GET; tarama altyapısı ASN'leri | Orta (KEV sonrası hacim patlar) |
| 2 | Enjeksiyon testi | Girdinin kabuğa ulaşıp ulaşmadığını görmek | T1190 | Ayraç + zararsız komut (`id`, `sleep`, DNS geri araması) içeren istekler; **istek süresinde sıçrama**; dış DNS sorgusu | **Yüksek** — en gürültülü an |
| 3 | İlk çalışma ve keşif | Hangi kullanıcıyla, hangi sistemde olduğunu öğrenmek | T1059.004/.003, T1033, T1082, T1016 | **Web kullanıcısının çalıştırdığı `id`, `whoami`, `uname`, `hostname`, `ipconfig`** | **Kesin** (auditd/Sysmon varsa) |
| 4 | Araç indirme | İkinci aşama yükü, tünel aracı, web shell | T1105 | Sunucudan/cihazdan `curl`/`wget`/`certutil`/`Invoke-WebRequest` ile dış istek; `/tmp`, `/dev/shm`, web kökünde yeni dosya | **Yüksek** (çıkış log'u + FIM) |
| 5 | Kalıcılık | Yeniden başlatmadan sağ çıkmak | T1505.003, T1053.003, T1543, T1136 | Web shell, `/etc/cron.d/` yeni dosya, `.pth`/systemd birimi, yeni yerel admin | **Kesin** |
| 6 | Kimlik bilgisi ve yapılandırma | Cihaz yapılandırması, VPN kullanıcı hash'leri, LDAP/AD servis hesabı | T1552.001, T1003, T1005 | Yapılandırma dosyasının arşivlenip web köküne kopyalanması veya dışarı gönderilmesi | Yüksek |
| 7 | Tünel ve yanal hareket | İç ağa geçmek | T1090, T1021.002, T1021.006 | **Firewall/VPN cihazından iç sunuculara SMB/WinRM**, ters kabuk, SOCKS tüneli | **Yüksek** — normalde hiç olmayan akış |
| 8 | Etki | AD ele geçirme, veri sızdırma, fidye | T1003.003, T1486 | NTDS.dit erişimi, toplu dosya şifreleme | Kesin ama geç |

**SOC açısından anahtar fikir:** 2. aşama istek katmanında görünür ama gürültülüdür ve 0-day'de imza olmayabilir. **3. aşama (web kullanıcısının kabuk çalıştırması) ve 7. aşama (sınır cihazından iç ağa akış)** saldırganın atlayamayacağı noktalardır: hangi payload kullanılırsa kullanılsın, bir komut **çalışmak zorundadır** ve bir süreç olarak görünür. Tespit yatırımını buraya yap.

### 2.2 Otomatik araç ve kampanya izi

| Gösterge | Neden oluşur |
|---|---|
| UA'da araç adı (commix, Nuclei, genel tarayıcılar) | Kullanıcı değiştirmezse araç kendini tanıtır |
| Aynı parametreye çok sayıda varyant: farklı ayraçlar, farklı kodlamalar | Araç hangi ayracın filtrelenmediğini dener |
| `sleep`/`ping -c`/`timeout` gibi gecikme komutları + yanıt süresinde düzenli artış | Zaman tabanlı kör doğrulama |
| Girdide rastgele alt alan adları + herkese açık OAST servisleri | Bant dışı (DNS) doğrulama |
| KEV/PoC yayımından sonraki **saatler içinde** aynı yola internet çapında istek dalgası | Botnet'ler ve fırsatçı gruplar PoC'yi otomasyona ekler; Ivanti Sentry CVE-2026-10520'de Shadowserver PoC yayımından kısa süre sonra arka kapılı cihazlar raporladı |
| Ayrıntılı tek bir istek, hiç tarama yok | Hedefli 0-day kullanımı (devlet destekli grup) — imza katmanına güvenme |

### 2.3 Atlatma sınıfları ve kural dayanıklılığı

Hazır atlatma listelerine gerek yok; kural yazarken şu sınıflara dayanıklı olman yeterli:

| Atlatma sınıfı | Fikir | Kural tarafında karşılığı |
|---|---|---|
| Kodlama katmanları | URL, çift URL, Unicode, satır sonu (`%0a`) ile ayraç | **İki kez decode et**, `%0a`/`%0d`'yi ayraç say |
| Boşluk ikamesi | Boşluk yerine değişken genişletme, sekme, ayraç | `${IFS}`, `$IFS`, `%09`, `{a,b}` kalıplarını tek başına şüpheli say |
| Komut adı gizleme | Tırnak, ters bölü, joker karakterle komut adını bölme; tam yol kullanma | Komut adı listesine değil **ayraç + kabuk yapısına** bak; uç noktada çalışan **gerçek süreç adını** gör |
| Kodlanmış yük | base64/hex ile yük, sonra çözüp kabuğa verme | `base64 -d`, `xxd -r`, PowerShell `-enc` — süreç komut satırında yakala |
| Taşıyıcı değişimi | JSON gövdesi, başlık, çerez, dosya adı, log satırı | Erişim log'u yetmez: WAF audit, cihaz log'u, **süreç telemetrisi** |
| Çıktısız çalışma | Kör/OAST/dosya yazma | Yanıt boyutu yerine süre, DNS ve FIM |

Sonuç: imza **ilk katmandır**; dayanıklı tespit **süreç ağacı** (web süreci → kabuk), **çıkış trafiği** ve **dosya bütünlüğü** katmanındadır. Komutun nasıl gizlendiği değişir; `www-data` kullanıcısının `sh` çalıştırması değişmez.

### 2.4 Gerçek vaka zaman çizelgesi: PAN-OS GlobalProtect — CVE-2024-3400 (Operation MidnightEclipse)

Volexity'nin UTA0218 olarak izlediği, Unit 42'nin *Operation MidnightEclipse* adını verdiği kampanya, sınır cihazında komut enjeksiyonunun tüm aşamalarını gösterir:

| Tarih (2024) | Ne oldu | Tespit edilebilecek iz |
|---|---|---|
| 26 Mart | Volexity'nin sonradan bulduğu en erken istismar denemeleri (test amaçlı, boş dosya oluşturma) | Web'den erişilebilir dizinlerde **sıfır baytlık** dosyalar |
| 7–10 Nisan | UPSTYLE Python arka kapısının barındırıldığı sunucu; 10 Nisan'da Volexity bir müşteride aktif istismarı gördü | Cihazdan dış IP'ye `update.py` indirme isteği |
| Kurulum | Arka kapı `system.pth` dosyasıyla Python her başladığında yükleniyor; komutları **web sunucusu hata log'una** yazılan özel satırlardan okuyor, çıktıyı bir **CSS dosyasına** yazıp 15 sn sonra eski hâline döndürüyordu | `sslvpn_ngx_error.log` içinde olağan dışı kalıplar; `bootstrap.min.css` boyut/zaman değişimi |
| Kalıcılık (yedek) | UPSTYLE başarısız olunca `/etc/cron.d/` altında her dakika uzak betik çekip kabuğa veren görev | Cihazdan dakikada bir aynı IP'ye `wget`/`curl` |
| Tünel | GOST ile SOCKS/ters tünel, SSH tabanlı ters kabuk | Cihazdan olağan dışı portlara uzun süreli bağlantı |
| Yanal hareket | Ayrıcalıklı servis hesabıyla **SMB ve WinRM** üzerinden iç ağa geçiş | **Firewall'un kendi IP'sinden** iç sunuculara SMB/WinRM — normalde hiç olmayan akış |
| Kimlik bilgisi | NTDS.dit, alan DPAPI yedek anahtarları, Windows olay log'ları, tarayıcı `Login Data`/`Cookies` | DC'de VSS/ntdsutil izleri, 4662 replikasyon olayları |
| 12 Nisan | Duyuru ve Unit 42 tehdit özeti; 14 Nisan'da hotfix'ler; CVSS 10.0 | — |

Etkilenen sürümler: PAN-OS 10.2, 11.0, 11.1 (GlobalProtect gateway/portal etkin). Düzeltmeler: 10.2.9-h1, 11.0.4-h1, 11.1.2-h3 ve sonrası. CVE-2024-3400; CVE-2024-20399 (Cisco NX-OS) ve CVE-2024-21887 (Ivanti) ile birlikte CISA/FBI'ın Temmuz 2024 *Secure by Design* uyarısını tetikleyen üç olaydan biriydi.

**Ders:** Cihazın kendisinde EDR yoktu; ama saldırganın **cihazdan dışarı** (araç indirme, tünel) ve **cihazdan içeri** (SMB/WinRM) yaptığı her şey firewall/NetFlow ve iç sunucu log'larında görülebilirdi. Sınır cihazı için tespit stratejisi: *cihaza değil, cihazın çevresine bak.*

### 2.5 İkinci örnek: NetScaler CVE-2026-88771 — log satırından komut

Eylül 2026'da açıklanan ve CISA'nın **27 Eylül 2026**'da KEV'e eklediği NetScaler ADC/Gateway açığı (CVSS 9.5), ikinci dereceden komut enjeksiyonunun ders kitabı örneğidir: kimlik doğrulamasız bir giriş isteğindeki **kullanıcı adı** log'a yazılıyor, root ile çalışan bir bakım betiği bu log satırının bir kısmını kabuğa veriyordu. Açık 0-day olarak kullanıldı; raporlanan istismar sonrası izler:

- `LogonPoint` altında gizli bir PHP web shell ve PHP'yi etkinleştirmek için değiştirilmiş `httpd.conf`,
- `ns.conf` içinde yeni **yerel süper kullanıcı** hesabı, `/bin/sh` izinlerinin değiştirilmesi,
- `/flash/nsconfig` dizininin arşivlenip dışarı gönderilmesi ve arşivin silinmesi,
- TCP/443 üzerinden ters kabuk, bazı kümelerde uzak yönetim aracı.

**SOC için ders:** İstek anında web log'unda yalnızca "garip bir kullanıcı adıyla başarısız giriş" görünür. **Kimlik doğrulama log'unda kullanıcı adı alanında kabuk karakterleri** başlı başına yüksek öncelikli bir sinyaldir (bkz. Splunk `05`).

### 2.6 Güncel CVE'ler ve KEV kayıtları (2024–2026)

| Yıl | Ürün / CVE | Özellik | Ders |
|---|---|---|---|
| 2026 | Citrix NetScaler ADC/Gateway – [CVE-2026-88771](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html) (CVSS 9.5) | Kimlik doğrulamasız, ikinci dereceden; kullanıcı adı → log → root betik; 0-day, KEV 27 Eylül 2026 | Log ve kimlik doğrulama alanları da enjeksiyon taşıyıcısıdır |
| 2026 | Fortinet FortiSandbox – [CVE-2026-39808 / CVE-2026-25089](https://threatprotect.qualys.com/2026/06/17/fortinet-fortisandbox-vulnerability-exploited-by-attackers-cve-2026-39808-cve-2026-25089-cve-2026-39813/) (CVSS 9.1) | Hazırlanmış HTTP isteğiyle kimlik doğrulamasız komut; 4.4.0–4.4.8 etkilendi, 4.4.9'da düzeltildi; KEV | Güvenlik ürünleri de sınır cihazıdır |
| 2026 | Ivanti Sentry – [CVE-2026-10520](https://securityaffairs.com/193530/hacking/cve-2026-10520-exploited-ivanti-sentry-gateways-compromised-shortly-after-patch-release.html) | Kimlik doğrulamasız, root RCE; PoC sonrası 10 Haziran 2026'da istismar, Shadowserver arka kapılı cihazlar raporladı | Yama yetmez: **yama öncesi ele geçirilmiş mi** kontrol et |
| 2025 | Cisco ISE / ISE-PIC – [CVE-2025-20281](https://www.bleepingcomputer.com/news/security/exploit-available-for-critical-cisco-ise-bug-exploited-in-attacks/) (+ CVE-2025-20337) | API'de kimlik doğrulamasız komut enjeksiyonu → root; 25 Haziran 2025 açıklama, 22 Temmuz'da aktif istismar; 3.3 Patch 7 / 3.4 Patch 2 | Kimlik altyapısı (NAC) ele geçirilirse ağ erişim politikası saldırganındır |
| 2024 | Palo Alto PAN-OS – [CVE-2024-3400](https://unit42.paloaltonetworks.com/cve-2024-3400/) (CVSS 10.0) | GlobalProtect; dosya oluşturma → komut; UPSTYLE | Bkz. §2.4 |
| 2024 | Ivanti Connect Secure – CVE-2024-21887 (+ CVE-2023-46805 auth bypass) | Web bileşeninde komut enjeksiyonu; auth bypass ile zincir | Yönetici-only açıklar + auth bypass = kimlik doğrulamasız RCE |
| 2024 | Cisco NX-OS – CVE-2024-20399 | CLI komut enjeksiyonu (yetkili), anahtarlarda kalıcılık | Ağ omurgası cihazları da hedef |

---

## 03 — Tespit: istek, süreç, ağ ve cihaz katmanları

### 3.1 Tespit katmanları

| Katman | Soru | Kaynak | Güven | Gecikme |
|---|---|---|---|---|
| L1 – İmza | İstekte kabuk ayracı + komut yapısı var mı? | Web erişim log'u, WAF (CRS **932xxx** RCE kuralları), IPS imzaları (vendor Threat ID'leri) | Düşük (0-day'de imza yok, FP) | Anında |
| L2 – Davranış | Biri parametreleri sistematik olarak mı deniyor? Yanıt süresi/boyutu sıçradı mı? Kullanıcı adında kabuk karakteri var mı? | Web log istatistikleri (`%D`, bytes), WAF audit, kimlik doğrulama log'u | Orta | Dakikalar |
| L3 – Süreç (çalışma) | Web/servis kullanıcısı kabuk veya keşif komutu çalıştırdı mı? | **auditd `execve`**, **Sysmon EID 1**, EDR, Falco | **Yüksek** — payload'dan bağımsız | Saniyeler |
| L4 – Etki | Sunucu/cihaz dışarıdan araç indirdi mi, tünel açtı mı, iç ağa SMB/WinRM yaptı mı? Web kökünde yeni dosya, yeni cron/hesap var mı? | Firewall/NetFlow/Zeek, proxy, DNS, FIM (Wazuh syscheck), cihaz yapılandırma farkı | **Kesin** | Dakikalar, ama saldırı başarılı demek |

Sınır cihazlarında L3 genellikle **yoktur** (EDR kurulamaz). Bu durumda L4'ü cihazın çevresinden kur: cihazın kendi IP'sinden başlayan çıkış ve iç akışlar, cihaz log'larının syslog ile dışarı aktarımı, vendor'un bütünlük denetim aracı (ör. Ivanti Integrity Checker Tool) ve düzenli yapılandırma yedeği farkı.

### 3.2 Loglama yapılandırması — önce görünürlük

#### Web sunucusu ve WAF

Erişim log formatı için #001'deki `combined_plus` formatını kullan: **yanıt süresi** (`%D` / `$request_time` / IIS `time-taken`) zaman tabanlı kör enjeksiyonun, **yanıt boyutu** sonuç dönen enjeksiyonun göstergesidir. Gövde için ModSecurity JSON audit log'u (#001 §3.2). OWASP CRS'te ilgili kurallar **932xxx (REQUEST-932-APPLICATION-ATTACK-RCE)** aralığındadır: Unix komut enjeksiyonu (932100/932105 ailesi), Windows komut enjeksiyonu (932110/932115 ailesi), Unix kabuk ifadeleri ve komut adları (932150–932160 ailesi), PowerShell (932120). Kural numaraları CRS sürümüne göre değişebilir — kendi kurulumunda `grep -n 'id:932' /usr/share/modsecurity-crs/rules/REQUEST-932-*.conf` ile doğrula.

#### Linux — auditd (L3'ün omurgası)

```bash
# /etc/audit/rules.d/50-web-exec.rules
# Web kullanıcısının çalıştırdığı her program (www-data UID'sini doğrula: id -u www-data)
-a always,exit -F arch=b64 -S execve -F euid=33 -k www_exec
-a always,exit -F arch=b32 -S execve -F euid=33 -k www_exec
# Uygulama sunucusu servis hesapları (tomcat, node, gunicorn) - UID'leri ortama göre
-a always,exit -F arch=b64 -S execve -F euid=998 -k app_exec
# Web kökü ve geçici dizinlere yazma
-w /var/www/ -p wa -k webroot_write
-w /etc/cron.d/ -p wa -k cron_change
-w /etc/crontab -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change
# Web kullanıcısının dışarı bağlantısı (gürültülüyse sadece kritik sunucularda)
-a always,exit -F arch=b64 -S connect -F euid=33 -F success=1 -k www_connect
```

`augenrules --load` ile yükle. `execve` olayında `EXECVE` kaydı **argümanları** (`a0`, `a1`…) taşır; `SYSCALL` kaydı `ppid`, `comm`, `exe`, `euid` ve `key` alanlarını verir. Wazuh'un auditd çözücüsü bunları `audit.*` alanlarına ayırır.

#### Windows — Sysmon ve yerleşik olaylar

| Olay | Neden |
|---|---|
| Sysmon **EID 1** (Process Create) — `ParentImage` = `w3wp.exe`, `httpd.exe`, `nginx.exe`, `php-cgi.exe`, `java.exe`, `tomcat*.exe`, `node.exe` ve `Image` = `cmd.exe`, `powershell.exe`, `pwsh.exe`, `whoami.exe`, `certutil.exe`, `bitsadmin.exe`, `rundll32.exe`, `mshta.exe` | Web sürecinden kabuk = L3'ün en net sinyali |
| Sysmon **EID 3** (Network Connection) — web süreci veya onun çocuğundan dış IP'ye | Araç indirme, ters kabuk |
| Sysmon **EID 11** (File Create) — `C:\inetpub\wwwroot\`, `%TEMP%` altında `.aspx`, `.ps1`, `.exe` | Web shell, ikinci aşama |
| Sysmon **EID 22** (DNS Query) — web sürecinden düşük itibarlı alan | OAST, C2 |
| Security **4688** (komut satırı denetimi açık: *Include command line in process creation events*) | Sysmon yoksa yedek |
| PowerShell **4104** (Script Block Logging) | Kodlanmış PowerShell'in açılmış hâli |

Sysmon yapılandırması için [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) veya [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) iyi başlangıçtır; web sunucusu ebeveynli tüm süreçleri dahil ettiğinden emin ol.

#### Sınır cihazları

| Kaynak | Ne ara |
|---|---|
| Cihaz sistem/web log'ları (syslog ile SIEM'e) | Web bileşeni hata log'larında olağan dışı satırlar, beklenmeyen hata patlamaları, kimlik doğrulama log'unda **kullanıcı adında kabuk karakterleri** |
| Cihaz threat/IPS log'u | Vendor'un yayımladığı Threat ID'leri (ör. CVE-2024-3400 için Palo Alto 95187/95189/95191) |
| Firewall/NetFlow — **cihazın kendi IP'si kaynak** | İnternete HTTP(S) indirme, olağan dışı portlar, iç ağa 445/5985/5986/22 |
| Yapılandırma yedeği farkı | Yeni yerel admin, yeni zamanlanmış görev, değişmiş web yapılandırması |
| Vendor bütünlük aracı | Ivanti ICT, Fortinet/Citrix'in yayımladığı IOC tarama betikleri |

#### Ağ ve DNS

- **DNS:** Sunucu/cihaz IP'lerinden yapılan **dış** DNS sorguları. Web sunucuları normalde birkaç bilinen alan adı sorgular; rastgele uzun alt alan adları bant dışı enjeksiyon doğrulamasıdır.
- **Çıkış kontrolü:** DMZ sunucularının ve sınır cihazlarının internete **başlattığı** bağlantılar varsayılan olarak reddedilmeli; izin listesi dışındaki her deneme log'lanmalı. Bu tek kontrol, araç indirme ve ters kabuk aşamasını hem engeller hem görünür kılar.

### 3.3 Log analizi: örnek bir saldırının izini okumak

[`ornek.log`](ornek.log) lab'da üretilmiş bir zinciri içerir. Okuma sırası (kim → ne ile → nasıl → sonuç):

1. **Kim?** `203.0.113.77` önce bir enjeksiyon aracı UA'sıyla `/tools/ping` endpoint'inin `host` parametresini yoklar.
2. **Ne ile?** Kabuk ayracı + zararsız komut içeren denemeler: biri 403 ile engellenir, bir diğeri **200 döner ve yanıt süresi ~5 saniyeye** çıkar (zaman tabanlı kör doğrulama — normal istek 40 ms).
3. **Nasıl gelişti?** ModSecurity aynı endpoint için CRS 932xxx **Warning** yazar ama isteği engellemez (anomali eşiği aşılmadı). Hemen ardından auditd, `www-data` (euid 33) kullanıcısının **`sh` ve `id`** çalıştırdığını, ardından **`curl`** ile dış bir adrese bağlandığını gösterir.
4. **Sonuç?** Kabuk + keşif + araç indirme = **başarılı RCE, kritik**. Aynı gün Windows tarafındaki IIS sunucusunda (`192.0.2.40` kaynaklı ayrı bir deneme) Sysmon, `w3wp.exe`'nin önce `cmd.exe /c whoami`, ardından doğrudan kodlanmış `powershell.exe -enc` başlattığını yazar → ikinci bir başarı.

**`ornek.log` satırlarında beklenen kurallar:**

| Dosya bölümü | İçerik | Beklenen Wazuh kuralı |
|---|---|---|
| access satır 1 | Normal ping isteği | — |
| access satır 2 | Enjeksiyon aracı UA | **100301** |
| access satır 3 | Ayraç + komut, 403 | 100300 |
| access satır 4 | Ayraç + gecikme komutu, 200, ~5 sn | 100300 → **100302** |
| access satır 5 | Komut ikamesi + `${IFS}` kalıbı, 200 | 100300 → **100302** |
| access satır 6 | Windows ayraçlı deneme, 403 | 100300 |
| modsec satır 1 | CRS 932 **Warning** (engellenmedi), `/tools/ping` | 100310 → **100311** |
| modsec satır 2 | CRS 932 Access denied 403 | 100310 |
| auditd satır 1 | `www-data` → `/usr/bin/dash` (key `www_exec`) | **100320** |
| auditd satır 2 | `www-data` → `/usr/bin/id` | 100320 → **100321** |
| auditd satır 3 | `www-data` → `/usr/bin/curl` | 100320 → **100322** |
| sysmon satır 1 | `w3wp.exe` → `cmd.exe` | **100330** (agent üzerinden) |
| sysmon satır 2 | `w3wp.exe` → `powershell.exe -enc` | 100330 → **100331** (agent üzerinden) |

### 3.4 Splunk

Tüm sorgular [`splunk.spl`](splunk.spl) dosyasında.

| # | Katman | Ne yakalar | Önerilen kullanım |
|---|---|---|---|
| 01 | L1 | Çift decode sonrası "ayraç + komut" yapı kategorileri | Avcılık, saatlik alert |
| 02 | L1 | Enjeksiyon aracı / tarayıcı UA'ları ve yüksek varyant | 15 dk alert, otomatik engelleme tetikleyicisi |
| 03 | L2 | **Zaman tabanlı kör enjeksiyon:** imzalı istekte yanıt süresinin endpoint tabanına göre sıçraması | Yüksek öncelikli alert |
| 04 | L1/L2 | CRS 932xxx: engellenen vs geçen, endpoint ayrımı | Dashboard + alert |
| 05 | L2 | **Kimlik doğrulama log'unda kullanıcı adında kabuk karakterleri** (ikinci dereceden, NetScaler tipi) | Yüksek öncelikli alert |
| 06 | L3 | **Linux:** web/servis kullanıcısının çalıştırdığı kabuk, keşif ve indirme araçları (auditd) | **Kritik** alert |
| 07 | L3 | **Windows:** web sunucusu sürecinin çocuğu olarak kabuk/LOLBin (Sysmon EID 1) | **Kritik** alert |
| 08 | L4 | Web kökünde yeni betik/çalıştırılabilir dosya (FIM / Sysmon EID 11) | Yüksek öncelikli alert |
| 09 | L4 | **Sınır cihazı/DMZ sunucusundan çıkış:** internete yeni hedef, iç ağa SMB/WinRM/SSH | **Kritik** alert |
| 10 | L4 | Sunucudan bant dışı DNS (OAST ve rastgele uzun alt alan adları) | Yüksek öncelikli alert |
| 11 | Hepsi | RBA: host ve IP üzerine katman puanları | Ana notable |
| 12 | — | Dashboard panelleri | SOC dashboard |

#### Sorgu yazarken uyulan prensipler

- **Normalize et, sonra eşleştir.** İki kez `urldecode()`, `lower()`, `%0a`/`%0d`/sekme ve `${IFS}`'i boşluk say.
- **Ayraç tek başına sinyal değildir.** `&` ve `;` URL'lerde meşru olarak geçer; kural **ayraç + komut adı/kabuk yapısı** birlikteliğine bakar.
- **Risk nesnesini doğru seç.** İstek katmanında `risk_object=src` (saldırgan IP); süreç ve etki katmanında `risk_object=dest` (ele geçirilen **host**) — asıl kurban sunucudur.
- **Ebeveyn–çocuk ilişkisi payload'dan dayanıklıdır.** L1'i atlatan saldırgan L3'ü atlatamaz; L3 kuralları en düşük FP ile en yüksek değeri verir.

#### Risk tabanlı alarm (RBA) mantığı

| Olay | Risk nesnesi | Puan |
|---|---|---|
| İmza eşleşmesi (403/400 ile engellenmiş) | src | +5 |
| İmza eşleşmesi, 200 | src | +15 |
| Enjeksiyon aracı UA / yüksek varyant | src | +25 |
| İmzalı istekte yanıt süresi sıçraması (kör doğrulama) | src + dest | +40 |
| WAF 932xxx tetiklendi ama engellenmedi | src + dest | +40 |
| Kullanıcı adında kabuk karakterleri (auth log) | src + dest | +50 |
| Sunucudan bant dışı DNS (OAST/rastgele alt alan) | dest | +60 |
| Web/servis kullanıcısı kabuk çalıştırdı | dest | +80 |
| Web kullanıcısı keşif komutu veya indirme aracı | dest | +100 |
| Sınır cihazından iç ağa SMB/WinRM veya internete yeni hedefe indirme | dest | +100 |

**Eşik:** 24 saatte host başına ≥ 80 → *Notable: Olası komut enjeksiyonu ile RCE*; IP başına ≥ 60 → *Olası komut enjeksiyonu taraması*.

### 3.5 Wazuh

Tüm kurallar ve ayarlar [`wazuh.xml`](wazuh.xml) dosyasında.

#### Yerleşik kurallar

`0245-web_rules.xml` içinde **31104** (yaygın web saldırısı — `cmd.exe`, `/etc/passwd` gibi kalıplar) ve **31106** (saldırı isteği 200 ile döndü); `0365-auditd_rules.xml` içinde **80700** (auditd mesajları tabanı); `0595-win-sysmon_rules.xml` içinde **61603** (Sysmon EID 1 süreç oluşturma) bulunur. Sürümünü doğrula:

```bash
grep -n -A6 'id="31104"\|id="31106"' /var/ossec/ruleset/rules/0245-web_rules.xml
grep -n -A4 'id="80700"' /var/ossec/ruleset/rules/0365-auditd_rules.xml
grep -n -A6 'id="61603"' /var/ossec/ruleset/rules/0595-win-sysmon_rules.xml
```

#### Özel kural seti (100300–100399)

| ID | Seviye | Mantık | Aktif yanıt |
|---|---|---|---|
| 100301 | 10 | Komut enjeksiyonu aracı User-Agent'ı (imzadan önce değerlendirilir) | firewall-drop 30 dk |
| 100300 | 8 | Gelişmiş imza: ayraç/ikame + komut adı, `${IFS}`, Windows kabuk yapıları (URL kodlu hâller dahil) | — |
| 100302 | 10 | İmzalı istek 200 döndü (çalışmış olabilir — süreç katmanıyla doğrula) | — |
| 100303 | 12 | 2 dk'da aynı IP'den 15+ imza | firewall-drop 30 dk |
| 100310 | 9 | ModSecurity CRS 932xxx tetiklendi | — |
| 100311 | 12 | CRS RCE kuralı tetiklendi ama istek **engellenmedi** | — |
| 100320 | 12 | auditd: web/servis kullanıcısı (key `www_exec`/`app_exec`) bir program çalıştırdı — kabuk dahil | — |
| 100321 | 14 | auditd: web kullanıcısı keşif komutu çalıştırdı (`id`, `whoami`, `uname`…) | — |
| 100322 | 14 | auditd: web kullanıcısı indirme/tünel aracı çalıştırdı (`curl`, `wget`, `nc`…) | — |
| 100330 | 12 | Sysmon: web sunucusu süreci kabuk/LOLBin başlattı | — |
| 100331 | 14 | Sysmon: web süreci altında kodlanmış PowerShell veya indirme komutu | — |

**Neden 100311 ve 1003[23]x'e otomatik engelleme yok?** Bu alarmlarda komut zaten çalışmıştır; saldırgan IP'sini engellemek kurulan arka kapıyı, cron görevini veya ters kabuğu (çoğunlukla başka IP'ye giden) kaldırmaz ve saldırgan başka IP'den devam eder. Gerekli aksiyon **host izolasyonu ve delil toplama**dır → insana veya onaylı SOAR adımına.

#### Test etme

```bash
/var/ossec/bin/wazuh-logtest
# ornek.log içinden "#" ile başlamayan bir satır yapıştır.
# auditd satırlarını tek tek yapıştır (SYSCALL kaydı; key alanı www_exec).
```

> Sysmon satırları gerçek ortamda agent'ın `eventchannel` toplayıcısından gelir; logtest'e düz JSON olarak yapıştırıldığında `windows_eventchannel` çözücüsüne düşmeyebilir. 100330/100331'i test etmek için lab'daki IIS sunucusunda Sysmon + Wazuh agent ile olay üret (bkz. §5.2). auditd çözücüsünün alan adları (`audit.key`, `audit.exe`, `audit.euid`) sürüme göre değişebilir — logtest çıktısında Phase 2 alanlarını kontrol et.

### 3.6 Ağ tarafı: PCAP ve Zeek ile doğrulama

**Wireshark görüntüleme filtreleri:**

```
http.request.uri matches "(%3b|%7c|%26%26|%60|%24%28|%0a)"
http.time > 4 && http.request.uri contains "/tools/"           # zaman tabanlı kör doğrulama
ip.src == <sunucu_ip> && (tcp.dstport == 4444 || tcp.flags.syn == 1 && !ip.dst == 10.0.0.0/8)
ip.src == <firewall_ip> && (tcp.dstport == 445 || tcp.dstport == 5985 || tcp.dstport == 5986)
dns && ip.src == <sunucu_ip> && dns.qry.name.len > 40
```

*Follow → HTTP Stream* ile isteğin gövdesini ve yanıtı incele: sonuç dönen enjeksiyonda komut çıktısı (ör. `uid=33(www-data)`) yanıt gövdesinde görünür.

**Zeek:** `conn.log`'da `id.orig_h` web sunucusu veya sınır cihazı olup `id.resp_h` kurum dışı olan **yeni** akışlar; `http.log`'da sunucu IP'sinden çıkan `curl`/`Wget` user-agent'lı istekler; `dns.log`'da sunucudan uzun/rastgele alt alan adı sorguları; `smb_files.log`/`dce_rpc.log`'da kaynağı firewall olan oturumlar.

### 3.7 Yanlış pozitif yönetimi

| FP kaynağı | Belirti | Çözüm |
|---|---|---|
| İç zafiyet tarayıcıları, DAST | Planlı zamanlarda yüksek hacim, imza alarmları | Tarayıcı IP allowlist'i + tarama takvimi |
| Meşru URL'ler | `&` parametre ayracı, `;` matris parametresi, arama kutusunda `cat` kelimesi | Ayraç + komut **yapısı**; tek başına komut adı alarm üretmesin, RBA puanı yazsın |
| Uygulamanın meşru alt süreçleri | PHP'nin `sendmail`, ImageMagick `convert`, PDF araçları çağırması; .NET uygulamasının `csc.exe` derlemesi | Ebeveyn + çocuk + komut satırı üçlüsüyle **dar** allowlist; kabuk (`sh -c`) üzerinden çağrılan meşru araçları geliştiriciyle birlikte kaldır |
| Sağlık kontrolü / izleme betikleri | Web kullanıcısıyla çalışan cron betikleri `curl localhost` | Hedefi `127.0.0.1`/iç izleme sistemi olanları dışla |
| Dağıtım (deploy) süreçleri | CI ajanının web kullanıcısıyla `git`, `composer`, `npm` çalıştırması | Değişiklik penceresi + deploy hesabını ayrı UID'ye taşı |
| Sınır cihazı güncellemeleri | Cihazın vendor güncelleme sunucusuna bağlanması | Vendor alan adları/IP blokları allowlist; **başka her şey alarm** |

**Kural sağlığı:** Her kural için aylık tetiklenme, TP oranı, ortalama triyaj süresi. L3 kuralları (100320–100331) için hedef: **sıfıra yakın FP** — her FP bir allowlist kaydına dönüşmeli, kural gevşetilmemeli.

---

## 04 — Önleme, sertleştirme ve olay müdahalesi

### 4.1 Asıl çözüm: kabuğu aradan çıkar

CISA/FBI'ın 2024 uyarısının özü tek cümledir: **kullanıcı girdisini komuttan ayrı tut.** Öncelik sırası:

1. **Kabuk çağırma, kütüphane kullan.** Ping için ICMP kütüphanesi, dosya işlemleri için dilin dosya API'si, arşiv için arşiv kütüphanesi.
2. Harici program şartsa **argüman dizisi** ile, kabuk olmadan çağır.
3. Girdiyi **allowlist** ile doğrula (IP adresi ise IP olarak ayrıştır; dosya adı ise karakter kümesini sınırla).
4. Argüman enjeksiyonuna karşı seçenek sonu işaretçisi (`--`) kullan ve `-` ile başlayan değerleri reddet.

```python
# Python – YANLIŞ: kabuk + metin birleştirme
os.system("ping -c 1 " + host)                          # TEHLİKELİ
subprocess.run(f"ping -c 1 {host}", shell=True)          # TEHLİKELİ

# DOĞRU: önce doğrula, sonra argüman listesi, shell=False (varsayılan)
import ipaddress, subprocess
ip = str(ipaddress.ip_address(host))                     # geçersizse ValueError
subprocess.run(["ping", "-c", "1", "--", ip], check=True, timeout=5)
```

```php
// PHP – mümkünse hiç exec kullanma. Zorunluysa:
if (!filter_var($host, FILTER_VALIDATE_IP)) { http_response_code(400); exit; }
$cmd = 'ping -c 1 ' . escapeshellarg($host);            // escapeshellarg = son çare, birincil savunma değil
// Daha iyi: proc_open() ile dizi biçiminde komut (PHP 7.4+) -> kabuk devreye girmez
$p = proc_open(['ping', '-c', '1', $host], [1 => ['pipe','w']], $pipes);
```

```javascript
// Node.js – exec() kabuk kullanır; execFile/spawn kullanmaz
const { execFile } = require('node:child_process');
const net = require('node:net');
if (!net.isIP(host)) throw new Error('geçersiz IP');
execFile('ping', ['-c', '1', host], { timeout: 5000 }, cb);   // shell: true VERME
```

```java
// Java – Runtime.exec("sh -c ...") yerine ProcessBuilder argüman listesi
if (!InetAddressValidator.getInstance().isValid(host)) throw new IllegalArgumentException();
new ProcessBuilder("ping", "-c", "1", host).redirectErrorStream(true).start();
```

```csharp
// C# – UseShellExecute=false ve ArgumentList (cmd.exe /c ile birleştirme YOK)
var psi = new ProcessStartInfo("ping") { UseShellExecute = false };
psi.ArgumentList.Add("-n"); psi.ArgumentList.Add("1"); psi.ArgumentList.Add(ip.ToString());
Process.Start(psi);
```

#### Dil ve framework tuzakları

| Dil | Tehlikeli | Güvenli karşılığı |
|---|---|---|
| Python | `os.system`, `os.popen`, `subprocess(..., shell=True)`, `commands` | `subprocess.run([...])`, `shlex.quote` yalnızca son çare |
| PHP | `system`, `exec`, `shell_exec`, `passthru`, backtick, `popen` | `proc_open([...])`, `escapeshellarg` (son çare), `disable_functions` |
| Node.js | `child_process.exec`, `execSync`, `spawn(..., {shell:true})` | `execFile`, `spawn` (shell'siz) |
| Java | `Runtime.exec("sh -c " + girdi)`, tek string `exec` | `ProcessBuilder(List)` |
| .NET | `cmd.exe /c` + string birleştirme, `UseShellExecute=true` | `ProcessStartInfo.ArgumentList` |
| Ruby | `system("..#{girdi}")`, backtick, `%x{}`, `Open3` string formu | `system("prog", arg1, arg2)` dizi formu |
| Perl/CGI (gömülü cihazlar) | `system($str)`, backtick, `open("... |")` | `system(LIST)`, `open` 3 argüman formu |
| Bash betikleri | Tırnaksız `$VAR`, `eval` | Her değişkeni `"$VAR"` ile tırnakla, `eval` kullanma |

**SAST:** CodeQL (`py/command-line-injection`, `js/command-line-injection`, `java/command-line-injection`), Semgrep (`subprocess-shell-true`, `dangerous-exec`), SonarQube. Sınır cihazı geliştiren üreticiler için CISA'nın tavsiyesi bu sınıfı **tamamen** taramak ve geçmiş açıkların kök neden analizini yapmaktır.

### 4.2 Katmanlı savunma kontrol listesi

| Katman | Kontrol | Etkisi |
|---|---|---|
| Kod | Kabuksuz çağrı, argüman listesi, allowlist doğrulama, `--` | Kök nedeni kapatır |
| Kod incelemesi | SAST kuralları, PR'da `shell=True`/`exec(` yasak listesi | Hatalı kalıbı merge öncesi yakalar |
| Çalışma ortamı | Web süreci **root değil**, ayrı UID; PHP `disable_functions`; konteynerde salt-okunur kök, `runAsNonRoot`, `no-new-privileges` | Başarılı enjeksiyonun etkisini daraltır |
| Süreç kısıtı | AppArmor/SELinux profilinde web sürecine `sh`/`curl` yürütme izni yok; Windows'ta WDAC/AppLocker, **ASR kuralları** | Kabuk açılmasını engeller |
| Dosya sistemi | `/tmp`, `/dev/shm`, web kökünü `noexec` bağla; web kökü web kullanıcısına salt-okunur | Araç indirme/web shell adımını kırar |
| Ağ | DMZ sunucuları ve sınır cihazları için **varsayılan-red çıkış**; cihazdan iç ağa yalnızca gerekli akışlar | Araç indirme, ters kabuk ve yanal hareketi engeller **ve** görünür kılar |
| Sınır cihazları | KEV takibi, saatler içinde yama, yönetim arayüzü internete kapalı, vendor bütünlük aracı, düzenli yapılandırma farkı, EOL cihaz envanteri | 2024–2026 olaylarının çoğunu önlerdi |
| WAF / IPS | CRS 932xxx (PL2+), vendor virtual patch/Threat ID'leri | Otomatik taramaları ve bilinen CVE'leri azaltır (0-day'i durdurmaz) |
| Görünürlük | auditd/Sysmon/EDR, cihaz log'larının syslog'u, çıkış log'u | Tespiti mümkün kılar (§3) |
| Test | DAST, pentest; ikinci dereceden enjeksiyon için log/kuyruk tüketen betiklerin incelenmesi | Kaçanı bulur |

### 4.3 Olay müdahale playbook'u (NIST SP 800-61 r2)

#### Triyaj karar ağacı

```
Alarm geldi
 ├─ Kaynak iç tarayıcı / onaylı pentest mi? ── Evet → kapat (FP), allowlist'i doğrula
 └─ Hayır
     ├─ Sadece imzalı istekler, hepsi 403/400, süreç/çıkış katmanında hiçbir şey yok mu?
     │      └─ Evet → DENEME (P3): IP engelle, ürün sürümünü KEV ile karşılaştır, kapat
     └─ Hayır
         ├─ 200 dönen imzalı istek / yanıt süresi sıçraması / WAF'tan geçen 932xxx / kullanıcı adında kabuk karakteri?
         │      └─ Evet → OLASI ÇALIŞMA (P2): aynı zaman aralığında host'un süreç, DNS ve çıkış log'larını kontrol et
         └─ Web kullanıcısı kabuk/keşif/indirme · web kökünde yeni dosya · yeni cron/hesap · sınır cihazından iç ağa veya internete yeni akış?
                └─ Evet → BAŞARI (P1) → L2 + IR, aşağıdaki adımlar
```

#### P1 adımları

| # | Aşama | Aksiyon | Sorumlu | Hedef süre |
|---|---|---|---|---|
| 1 | Tespit & analiz | İlk başarılı isteği, çalışan komutları (auditd/Sysmon), indirilen dosyaları ve dış IP/alan adlarını zaman çizelgesine dök; **aynı açıktan etkilenen diğer cihaz/sunucuları** envanterden çıkar | L1 → L2 | 30 dk |
| 2 | Delil koruma | **İzolasyondan önce** bellek imajı (Linux: AVML/LiME; Windows: WinPmem), çalışan süreç ve bağlantı listesi; disk imajı veya vendor'un adli destek paketi (tech-support bundle); log'ları değiştirilemez depoya al | DFIR | 1 sa |
| 3 | Kontrol altına alma | Host'u ağdan izole et (EDR izolasyonu / switch portu / güvenlik grubu); sınır cihazında yönetim ve portal servislerini kapat veya yedek cihaza geç; dış C2/indirme IP'lerini perimetrede engelle | L2 + ağ ekibi | 1 sa |
| 4 | Kapsam | Cihazın/sunucunun eriştiği **tüm kimlik bilgileri** (LDAP/AD servis hesabı, VPN kullanıcıları, API anahtarları, sertifikalar) ihlal edilmiş sayılır; cihazdan iç ağa giden oturumları ve hedef hostları incele (§2.4: SMB/WinRM, NTDS.dit) | DFIR + IAM | 4 sa |
| 5 | Kalıcılık temizliği | Web shell, cron/systemd, `.pth`/başlangıç betikleri, yeni yerel hesaplar, değiştirilmiş web yapılandırması. **Sınır cihazında tercih: fabrika ayarına dön + temiz imaj + yapılandırmayı elle doğrulayarak geri yükle** — yama tek başına arka kapıyı silmez | Sistem + vendor | 24 sa |
| 6 | Temizleme | Yama/güncelleme (KEV ise acil); kod düzeltmesi + aynı kalıbı tüm kod tabanında SAST ile ara; çıkış kısıtlarını uygula | Uygulama + sistem | 48 sa |
| 7 | Kimlik bilgisi rotasyonu | Cihazdaki servis hesapları, yerel admin parolaları, VPN kullanıcı parolaları (hash'ler alındıysa), TLS özel anahtarları ve sertifikalar, API token'ları; AD etkilendiyse krbtgt çift sıfırlama (bkz. #03x serisi) | IAM | 48 sa |
| 8 | Kurtarma | Temiz sistemi devreye al; 30 gün yükseltilmiş izleme: aynı IP/alan adları, aynı dosya yolları, cihazdan çıkış akışları | SOC | — |
| 9 | Yasal bildirim | Kişisel veri sızdıysa KVKK m.12 uyarınca Kurul'a **72 saat** içinde bildirim; sektörel düzenlemeler (BDDK, EPDK, USOM koordinasyonu) | Hukuk + CISO | 72 sa |
| 10 | Öğrenilen dersler | Kök neden; yama süresi neden uzadı; eksik telemetri (cihaz log'u, çıkış log'u) kalıcı olarak eklendi mi; kural güncellemesi | Tüm ekipler | 2 hafta |

#### Analist ticket şablonu

```
Başlık     : [P1] Olası OS command injection ile RCE - <host/cihaz> - <ürün/CVE>
Tetikleyen : Wazuh 100320-100331 / 100311 · Splunk RBA dest=<host> risk=<puan>
Zaman      : İlk deneme <ts> · İlk çalışma (süreç) <ts> · İlk dış bağlantı <ts> · Son aktivite <ts>
Kaynak     : <saldırgan IP listesi>, ASN, itibar; indirme/C2 IP ve alan adları
Vektör     : <endpoint + parametre / başlık / kullanıcı adı alanı>, ürün ve sürüm, KEV durumu
Çalışan    : <kullanıcı (www-data/IIS AppPool/root)>, <komutlar ve süreç ağacı>
Kalıcılık  : <web shell yolu, cron, yeni hesap, değişen yapılandırma>
Yanal      : <cihazdan iç ağa oturumlar, hedef hostlar>
Etki       : <okunan yapılandırma/kimlik bilgileri, veri, kişisel veri: evet/hayır>
Aksiyonlar : <izolasyon, delil (bellek/disk), engelleme, servis kapatma>
Sonraki    : <yeniden kurulum/yama, kimlik rotasyonu, sorumlular>
```

### 4.4 SOAR otomasyonu (Shuffle)

1. **Tetik:** Wazuh integration (`<integration><name>shuffle</name><hook_url>...</hook_url><rule_id>100301,100303,100311,100320,100321,100322,100330,100331</rule_id></integration>`).
2. **Zenginleştirme:** Kaynak IP ve indirme hedefi için VirusTotal/AbuseIPDB/GreyNoise (internet çapında tarayıcı mı, hedefli mi?); Splunk'tan host'un 24 saatlik RBA puanı ve son 1 saatteki çıkış bağlantıları; varlık envanterinden ürün/sürüm ve CISA KEV eşleşmesi.
3. **Dallanma:**
    - 100301/100303 → WAF/firewall API ile IP engelle, P3 vaka, otomatik kapat.
    - 100311 → P2 vaka; ilgili host için `06`/`07` sorgularını aynı zaman aralığında çalıştır, sonuç varsa P1'e yükselt.
    - 100320–100331 → P1 vaka; Teams/Slack'e L2 bildirimi; **onay butonu** ile: EDR üzerinden host izolasyonu, perimetrede indirme/C2 IP'lerini engelleme, DFIR için bellek toplama görevini başlatma. Sınır cihazında otomatik aksiyon yok — ağ ekibi elle karar verir.
4. **Kapanış:** Vakaya tüm zenginleştirme, süreç ağacı, ham log bağlantıları ve yapılan aksiyonlar eklenir.

---

## 05 — Pratik: odalar, lab ve kaynaklar

### 5.1 Önerilen sıra

| # | Platform | Oda / ders | Odak |
|---|---|---|---|
| 1 | TryHackMe | [Command Injection](https://tryhackme.com/r/room/oscommandinjection) (Premium) | Kök neden, sonuç dönen ve kör türler, Linux/Windows farkı, önleme |
| 2 | PortSwigger | [Web Security Academy – OS command injection](https://portswigger.net/web-security/os-command-injection) | Ücretsiz lab'lar: sonuç dönen, zaman tabanlı, çıktı yönlendirme, bant dışı |
| 3 | LetsDefend | [Detecting Web Attacks](https://app.letsdefend.io/training/lessons/web-attacks-101) | Web log'undan komut enjeksiyonu tespiti dersi |
| 4 | LetsDefend | [Detecting Command Injection Attacks (blog)](https://letsdefend.io/blog/detecting-command-injection-attacks) | Analist bakışıyla özet: log, süreç ve araç izleri |
| 5 | LetsDefend | Monitoring kuyruğundaki "Command Injection" web alarmları | Gerçek ticket akışı: triyaj, log yönetimi, kapatma |
| 6 | DVWA | *Command Injection* modülü (low → high) | Kendi lab'ında hem saldırı hem L1–L4 tespit katmanlarını gözlemleme |

### 5.2 Kendi detection lab'ın

```
[Kali / saldırgan VM] ──HTTP──> [Ubuntu: Apache/Nginx + ModSecurity CRS + DVWA]
                                      │  auditd (www_exec, webroot_write, cron_change)
                                      │  Wazuh agent (access/error/audit log + FIM)
                                      ▼
[Windows Server: IIS + Sysmon + Wazuh agent] ────> [Wazuh manager] [Splunk Free/Dev]
          ▲                                               ▲
          └──── [pfSense / OPNsense: çıkış log'u, NetFlow] ┘
```

1. DVWA'yı kur; #001 §3.2'deki log formatlarını uygula (yanıt süresi alanı şart).
2. §3.2'deki auditd kurallarını yükle; `ausearch -k www_exec` ile çalıştığını doğrula.
3. [`wazuh.xml`](wazuh.xml) Bölüm C'yi agent'lara, A ve B'yi manager'a uygula.
4. DVWA *Command Injection* modülünü "low" seviyede kullan: her denemede hangi katmanın (erişim log'u / WAF / auditd / çıkış log'u) sinyal ürettiğini bir tabloya not et. Seviyeyi "high"a çıkardığında **L1 imzalarının bir kısmı susarken auditd'nin hâlâ `sh` gördüğünü** gözlemle.
5. Windows tarafında IIS'e basit bir test uygulaması koy (yalnızca lab ağında) ve Sysmon EID 1'de `w3wp.exe` ebeveynli süreçleri izle.
6. Firewall'da DMZ için varsayılan-red çıkış kuralı yaz; DVWA sunucusundan dışarı indirme denemesinin hem engellendiğini hem log'landığını gör.
7. Kuralları [`ornek.log`](ornek.log) ile `wazuh-logtest` üzerinden doğrula.

### 5.3 Kendini test et

1. Erişim log'unda imza yokken (0-day, gövdede payload) bir komut enjeksiyonunun **başarılı** olduğunu hangi iki katmandan anlarsın?
2. Zaman tabanlı kör komut enjeksiyonunu erişim log'unda yakalamak için hangi alan gereklidir ve neden varsayılan Apache `combined` formatı yetmez?
3. NetScaler CVE-2026-88771 tipi ikinci dereceden enjeksiyonda neden istek anında web sunucusu → kabuk süreci görmeyebilirsin; hangi sinyale bakarsın?
4. Sınır cihazına EDR kuramadığında CVE-2024-3400 benzeri bir ihlali hangi telemetriyle yakalarsın?
5. Neden 100320–100331 kurallarına otomatik IP engelleme bağlamadık; bunun yerine hangi aksiyonlar gerekir?

<details><summary>Cevaplar</summary>

1. **Süreç katmanı** (auditd `execve` / Sysmon EID 1: web kullanıcısı veya web süreci altında kabuk, keşif komutu) ve **etki katmanı** (sunucudan dış bağlantı, web kökünde yeni dosya, yeni cron/hesap). İkisi de payload'dan bağımsızdır.
2. **Yanıt süresi** alanı (`%D`, `$request_time`, `time-taken`). `combined` formatı süreyi yazmaz; imzalı isteklerde süre sıçraması kör doğrulamanın tek erişim log'u izidir.
3. Komutu çalıştıran web sunucusu değil, log'u daha sonra işleyen **bakım/cron betiğidir**; ebeveyn süreç farklıdır ve zaman kayar. Bakılacak sinyal: **kimlik doğrulama log'unda kullanıcı adı alanında kabuk karakterleri** ve ardından cihazdan beklenmeyen süreç/çıkış trafiği.
4. Cihazın çevresinden: **cihazın kendi IP'sinden** internete indirme/tünel bağlantıları ve iç ağa SMB/WinRM (firewall/NetFlow/Zeek), cihaz log'larının syslog ile SIEM'e aktarımı (hata log'unda olağan dışı satırlar), vendor IPS Threat ID'leri, yapılandırma farkı ve vendor bütünlük aracı.
5. Komut zaten çalışmıştır; IP engellemek arka kapıyı, cron'u ya da başka IP'ye giden ters kabuğu kaldırmaz, saldırgan başka IP'den devam eder. Gerekenler: host izolasyonu, bellek/disk delili, kalıcılık temizliği (sınır cihazında temiz imaj), cihazdaki tüm kimlik bilgilerinin rotasyonu — insan onaylı.

</details>

### 5.4 Kaynaklar

- [CISA & FBI – Secure by Design Alert: Eliminating OS Command Injection Vulnerabilities (Temmuz 2024)](https://www.cisa.gov/news-events/alerts/2024/07/10/cisa-and-fbi-release-secure-design-alert-eliminating-os-command-injection-vulnerabilities)
- [OWASP OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [MITRE CWE-78](https://cwe.mitre.org/data/definitions/78.html) · [CWE-88](https://cwe.mitre.org/data/definitions/88.html) · [ATT&CK T1190](https://attack.mitre.org/techniques/T1190/) · [T1059.004](https://attack.mitre.org/techniques/T1059/004/) · [T1105](https://attack.mitre.org/techniques/T1105/)
- [OWASP Core Rule Set](https://coreruleset.org/) (932xxx RCE kuralları)
- [Unit 42 – CVE-2024-3400 / Operation MidnightEclipse](https://unit42.paloaltonetworks.com/cve-2024-3400/) · [Tenable – CVE-2024-3400](https://it.tenable.com/blog/cve-2024-3400-zero-day-vulnerability-in-palo-alto-networks-pan-os-globalprotect-gateway) · [Volexity bulguları özeti](https://www.hendryadrian.com/?p=12496)
- [The Hacker News – NetScaler CVE-2026-88771 istismar sonrası](https://thehackernews.com/2026/10/citrix-netscaler-post-exploitation.html) · [Picus – CVE-2026-88771 açıklaması](https://www.picussecurity.com/test-27/blog/cve-2026-88771-citrix-netscaler-pre-auth-command-injection-explained)
- [Qualys – FortiSandbox CVE-2026-39808 / CVE-2026-25089](https://threatprotect.qualys.com/2026/06/17/fortinet-fortisandbox-vulnerability-exploited-by-attackers-cve-2026-39808-cve-2026-25089-cve-2026-39813/) · [Security Affairs – Ivanti Sentry CVE-2026-10520](https://securityaffairs.com/193530/hacking/cve-2026-10520-exploited-ivanti-sentry-gateways-compromised-shortly-after-patch-release.html) · [BleepingComputer – Cisco ISE CVE-2025-20281](https://www.bleepingcomputer.com/news/security/exploit-available-for-critical-cisco-ise-bug-exploited-in-attacks/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Splunk Security Content (ESCU)](https://research.splunk.com/) — "web server spawning shell", "command injection" aramaları
