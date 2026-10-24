# #001 — SQL Injection (SQLi)

> Kullanıcı girdisinin SQL sorgusuna **veri olarak değil, kod olarak** karışması. 25 yıldır en çok sömürülen web zafiyetlerinden biri; 2023'te MOVEit Transfer'deki tek bir SQLi (CVE-2023-34362) 2.700'den fazla kurumu etkiledi, 2025–2026'da FortiWeb, FortiClient EMS ve Drupal Core SQLi'leri CISA KEV listesine girdi.

## Özet kartı

| Alan | Değer |
|---|---|
| Kategori | Web uygulama saldırıları (Web #1) |
| OWASP Top 10 (2021) | A03:2021 – Injection |
| OWASP API Top 10 (2023) | API8:2023 – Security Misconfiguration (dolaylı), API10 Unsafe Consumption |
| CWE | CWE-89 (SQL Injection), CWE-564 (Hibernate), CWE-943 (genel data query) |
| CAPEC | CAPEC-66, CAPEC-7 (Blind), CAPEC-108 (Command line execution through SQLi), CAPEC-470 |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application · T1505.003 Web Shell · T1059 Command Interpreter · T1005/T1213 Data from Information Repositories · T1048 Exfiltration over Alternative Protocol (OOB) |
| Etki (CIA) | **C:** toplu veri sızıntısı · **I:** veri değiştirme, yetkisiz admin oluşturma · **A:** tablo silme, ağır sorgu ile DoS |
| Tipik CVSS 3.1 | 7.5 – 9.8 (`AV:N/AC:L/PR:N/UI:N` → kritik) |
| Saldırgan seviyesi | Script kiddie (sqlmap) → İleri (WAF bypass, second-order, OOB) |
| SOC önceliği | Deneme: Düşük/Orta · Başarı belirtisi: **Kritik** (veri ihlali varsayılır) |
| Wazuh kural bloğu | 100100 – 100199 |

## 30 saniyede SOC özeti

1. **Ne arıyorum?** URL/POST gövdesinde `'`, `UNION SELECT`, `SLEEP(`, `information_schema`, `OR 1=1`; User-Agent'ta `sqlmap`.
2. **Deneme mi, başarı mı?** Yanıt kodu `200` + normalden çok büyük yanıt boyutu + DB'de meta tablo sorgusu + web dizininde yeni dosya + DB servisinin kabuk açması = başarı.
3. **İlk aksiyon?** Deneme → IP engelle, kapat. Başarı → endpoint'i virtual patch ile kapat, DB hesabının parolasını döndür, delil topla, L2/IR'a eskale et.

## İçindekiler

1. [Teori: SQL Injection nasıl çalışır?](#01--teori-sql-injection-nasıl-çalışır)
2. [Saldırı akışı ve her aşamanın izi](#02--saldırı-akışı-ve-her-aşamanın-izi)
3. [Tespit: log mimarisinden korelasyona](#03--tespit-log-mimarisinden-korelasyona)
4. [Önleme, sertleştirme ve olay müdahalesi](#04--önleme-sertleştirme-ve-olay-müdahalesi)
5. [Pratik: odalar, lab ve kaynaklar](#05--pratik-odalar-lab-ve-kaynaklar)

**Bu klasördeki diğer dosyalar (kopyala-yapıştır için):**

| Dosya | İçerik |
|---|---|
| [`splunk.spl`](splunk.spl) | 12 SPL sorgusu, numaralı bölümler halinde |
| [`wazuh.xml`](wazuh.xml) | Özel kurallar (100100–100199) + aktif yanıt + agent ayarları |
| [`ornek.log`](ornek.log) | Kuralları test etmek için örnek access ve ModSecurity log satırları |

## 01 — Teori: SQL Injection nasıl çalışır?

### 1.1 Kök neden: kod ile verinin karışması

Uygulama veritabanına iki şey gönderir: **sorgunun yapısı** (geliştiricinin kodu) ve **değerler** (kullanıcı verisi). Güvenli sistemde bu ikisi ayrı kanallardan gider. SQLi, ikisinin **aynı metin içinde birleştirilmesiyle** doğar; veritabanı motoru hangi karakterin kimden geldiğini bilemez ve hepsini tek bir SQL metni olarak ayrıştırır. Kullanıcı verisi SQL söz dizimine ait karakterler içerdiğinde sorgunun anlamı değişir.

#### DB motoru bir sorguyu nasıl işler?

| Aşama | Ne olur | SQLi ile ilişkisi |
|---|---|---|
| 1. Lexing / Parsing | Metin token'lara ayrılır (anahtar kelime, literal, operatör) | Zafiyet burada oluşur: veri, token sınırını aşıp kod gibi okunur |
| 2. Binding / Semantic | Tablo/kolon adları çözülür, **yetkiler kontrol edilir** | Uygulama hesabının yetkisi, saldırının ulaşabileceği tavanı belirler |
| 3. Optimization | Yürütme planı oluşur | — |
| 4. Execution | Sonuç döner | Sonucun kullanıcıya nasıl yansıdığı SQLi türünü belirler |

**Prepared statement** 1. aşamayı kullanıcı verisi gelmeden önce yapar. Yer tutucuya (`?`) bağlanan değer bir daha ayrıştırılmaz; içinde ne olursa olsun yalnızca bir veri değeridir. Çözüm budur — sorun, onu her yerde uygulamamaktır.

### 1.2 Saldırı yüzeyi: girdi nereden gelir?

HTTP isteğinin **her parçası** istemcinin kontrolündedir. Analist için kritik nokta: her kaynak farklı bir log'da görünür (veya hiç görünmez).

| Kaynak | Örnek | SOC görünürlüğü |
|---|---|---|
| Query string | `/urun?id=5` | Erişim log'unda var |
| POST form gövdesi | login formları | Erişim log'unda **yok** → WAF/uygulama log'u gerekir |
| JSON / XML gövdesi | REST/GraphQL API'leri | Erişim log'unda yok; bazı WAF'lar JSON'u ayrıştırmaz |
| HTTP header | `User-Agent`, `X-Forwarded-For`, `Authorization` | UA ve Referer combined formatta var; diğerleri yok. FortiWeb CVE-2025-25257 `Authorization` header'ındaydı |
| Cookie | dil, tercih, oturum değerleri | Varsayılan olarak yok |
| URL path | `/api/users/5` | Var |
| Second-order | DB'ye önceden kaydedilmiş veri | İlk istekte zararsız görünür; tetiklendiği istek farklıdır |

### 1.3 SQLi türleri — sonucun hangi kanaldan döndüğüne göre

| Tür | Mekanizma (kavramsal) | Saldırganın gördüğü | Savunucunun gördüğü iz |
|---|---|---|---|
| **Error-based** | Sorgu bilerek hataya düşürülür; DB hata mesajı veriyi taşır | Sayfadaki ayrıntılı DB hatası | 500 yanıtları, uygulama log'unda SQL syntax/conversion hataları |
| **UNION-based** | Orijinal sorgunun sonucuna ikinci bir SELECT'in sonucu eklenir | Sayfada başka tablolardan veri | `UNION`/`SELECT` içeren istekler, aynı endpoint'te ani büyük yanıt |
| **Boolean blind** | Koşul doğru/yanlış olduğunda sayfa farklı davranır; veri bit bit çıkarılır | Sayfanın iki farklı hali | Aynı parametreye yüzlerce–binlerce istek, yanıt boyutunun iki değer arasında gidip gelmesi |
| **Time-based blind** | Koşula bağlı gecikme fonksiyonu çalışır | Yanıt süresi | Yanıt sürelerinin sabit bir değerde (ör. 5 sn) kümelenmesi, uzun süreli düşük hızlı tarama |
| **Out-of-band (OOB)** | DB, sonucu DNS/HTTP/SMB ile dışarı gönderir | Kendi sunucusuna gelen bağlantı | **DB sunucusundan internete DNS/SMB trafiği** — normalde hiç olmamalı |
| **Second-order** | Kaydedilen veri, sonraki başka bir sorguda çalışır | Gecikmeli etki | İlk istek temiz görünür; tespit en zor tür |
| **Stacked queries** | Tek istekte birden fazla ifade çalışır | Ek komutun etkisi | DB audit'te beklenmeyen DDL/DML, yeni kullanıcı, yetki değişikliği |

**Neden önemli?** Blind ve time-based türler, saldırganı **binlerce istek** atmaya zorlar. Bu, SOC için en büyük fırsattır: hacim ve tekrar, imzadan bağımsız olarak tespit edilebilir.

### 1.4 Veritabanına göre risk farkları

SQLi'nin etkisi, DB motorunun sunduğu yan yeteneklere ve uygulama hesabının yetkisine bağlıdır.

| DB | Yüksek riskli yetenek | Savunma ayarı |
|---|---|---|
| MySQL / MariaDB | Dosya okuma/yazma fonksiyonları (`FILE` yetkisi) | `FILE` yetkisini kaldır, `secure_file_priv` ayarla |
| MSSQL | `xp_cmdshell`, `OPENROWSET`, linked server | `xp_cmdshell` kapalı, uygulama hesabı `sysadmin` değil |
| PostgreSQL | Sunucuda program çalıştırma (`pg_execute_server_program` rolü) | Uygulama hesabı süper kullanıcı değil, bu rol verilmez |
| Oracle | Ağ paketleri (`UTL_HTTP`, `UTL_INADDR`) | `PUBLIC`'ten bu paketlerin EXECUTE yetkisini geri al |
| SQLite | Ek veritabanı dosyası bağlama | Uygulama dizin izinlerini kısıtla |

**Ders:** Aynı SQLi, `SELECT`-only bir hesapta "veri sızıntısı", `sa`/`root` hesabında "sunucunun ele geçirilmesi" demektir. En az yetki ilkesi etkiyi bir kademe düşürür.

### 1.5 Neden hâlâ bu kadar yaygın?

- **Parametreleştirilemeyen yerler:** `ORDER BY` kolonu, tablo adı, sıralama yönü — geliştirici buralarda string birleştirmeye döner.
- **ORM kaçış kapıları:** `raw()`, `query()`, `Sequelize.literal`, Hibernate HQL string birleştirme.
- **Stored procedure yanılgısı:** Prosedür içinde dinamik SQL (`EXEC(@sql)`) varsa zafiyet aynen devam eder.
- **Kurumsal ürünler:** 2023–2026'nın büyük SQLi olayları özel kodlarda değil, internete açık **hazır ürünlerde** (MOVEit, FortiWeb, FortiClient EMS, Drupal) yaşandı → SOC için yama ve KEV takibi en az kod güvenliği kadar önemli.

---

## 02 — Saldırı akışı ve her aşamanın izi

> Bu bölüm saldırıyı **savunucu gözüyle** anlatır: saldırgan her aşamada neyi hedefler ve geride hangi iz kalır. Uygulamalı pratik için [§5](#05--pratik-odalar-lab-ve-kaynaklar)'deki yasal lab'ları kullan.

### 2.1 Aşamalar ve MITRE ATT&CK eşleşmesi

| # | Aşama | Saldırganın hedefi | ATT&CK | Bıraktığı iz | Tespit fırsatı |
|---|---|---|---|---|---|
| 1 | Keşif | Parametreli endpoint, API, login formu bulmak | T1595.002 Vulnerability Scanning, T1594 | Kısa sürede çok sayıda farklı URL, 404 artışı, crawler/scanner User-Agent'ları | Orta |
| 2 | Doğrulama (probe) | Girdinin sorguyu bozup bozmadığını görmek | T1190 | Özel karakter içeren istekler, **500 hata artışı**, uygulama log'unda SQL syntax hatası | **Yüksek** — en gürültülü an |
| 3 | Parmak izi | DB motorunu ve sürümünü öğrenmek | T1190 | DB'ye özgü fonksiyon adları içeren istekler | Yüksek |
| 4 | Yapı çıkarma | Tablo ve kolon adlarını öğrenmek | T1190 | DB'de **meta tablo** (`information_schema`, `sys.*`, `all_tables`) sorguları — uygulama normalde bunları sorgulamaz | **Çok yüksek** (DB audit varsa) |
| 5 | Veri çıkarma | Kullanıcı, müşteri, kart, oturum tablolarını almak | T1005, T1213 | Büyük yanıt boyutu, blind ise binlerce tekrarlı istek, uzun süreli oturum | Yüksek |
| 6 | Yetki / OS'a geçiş | Dosya yazma, komut çalıştırma, web shell | T1505.003, T1059 | Web dizininde **yeni betik dosyası**, DB/web servisinin alt süreç açması, dışarı bağlantı | **Kesin** (EDR/Sysmon varsa) |
| 7 | Yanal hareket / sızdırma | İç ağa yayılmak, veriyi dışarı taşımak | T1021, T1048, T1567 | DB/web sunucusundan alışılmadık iç/dış bağlantılar | Yüksek |

**SOC açısından anahtar fikir:** Saldırgan 2. ve 4. aşamadan geçmeden veriye ulaşamaz. Bu iki aşama hem web log'unda hem DB log'unda iz bırakır. Tespit stratejisi bu "geçilmesi zorunlu" noktalara yerleştirilir.

### 2.2 Otomatik araç izi (sqlmap ve benzerleri)

Gerçek dünyada SQLi denemelerinin büyük kısmı otomatik araçlarla yapılır. Araçlar hız kazandırır ama **çok belirgin parmak izi** bırakır:

| Gösterge | Neden oluşur |
|---|---|
| Varsayılan User-Agent'ta araç adı | Kullanıcı değiştirmezse araç kendini tanıtır |
| Tek IP'den tek endpoint'e dakikada yüzlerce istek | Her teknik ve her karakter için ayrı istek gerekir |
| Aynı parametrede sistematik olarak değişen değerler | Araç teknikleri sırayla dener |
| Rastgele sayı içeren tekrarlayan kalıplar | Araç, doğru/yanlış yanıtı ayırt etmek için benzersiz işaretler kullanır |
| Yanıt sürelerinin sabit bir gecikmede kümelenmesi | Time-based teknik |
| Saatlerce süren, düşük ve sabit hızlı trafik | Blind veri çıkarma + rate-limit'e takılmama çabası |

Gelişmiş saldırgan User-Agent'ı değiştirir, istekleri yavaşlatır, proxy/Tor havuzu kullanır. Bu yüzden **yalnızca imzaya dayanan tespit yetmez**; davranış (hacim, tekrar, boyut, süre) ve sonuç (DB/OS izi) katmanları gerekir — bkz. [§3](#03--tespit-log-mimarisinden-korelasyona).

### 2.3 WAF atlatma — kural yazarken neyi bilmelisin?

Saldırganlar imza tabanlı kuralları **görüntüyü değiştirerek** atlatmaya çalışır. Ayrıntılı teknik listesine gerek yok; kural yazarken şu dört sınıfa dayanıklı olman yeterli:

| Atlatma sınıfı | Fikir | Kural tarafında karşılığı |
|---|---|---|
| Kodlama | URL / çift URL / Unicode / hex kodlama | Log'u eşleştirmeden önce **tekrar tekrar decode et** |
| Büyük/küçük harf ve boşluk oyunu | Anahtar kelimeler arası yorum, tab, satır sonu | **Lowercase + boşluk/yorum normalizasyonu**, regex'te `\s` ve yorum alternatifi |
| Eşdeğer ifadeler | Aynı işi yapan farklı fonksiyon/operatör | Tek kelimeye değil **kategoriye** bak (meta tablo erişimi, gecikme fonksiyonları) |
| Farklı taşıyıcı | JSON, XML, multipart, header, cookie | Sadece URL'ye değil **gövde ve header'lara** da bak (WAF audit log) |

Bu yüzden olgun bir tespit mimarisi imzayı yalnızca ilk katman olarak kullanır; asıl güven **sonuç göstergelerinden** gelir (anormal yanıt, DB meta sorgusu, yeni dosya, kabuk süreci).

### 2.4 Gerçek vaka zaman çizelgesi: MOVEit Transfer (CVE-2023-34362)

Cl0p grubunun kampanyası, aşamaların gerçek hayatta nasıl göründüğünü gösterir:

| Aşama | Ne oldu | Tespit edilebilecek iz |
|---|---|---|
| İlk erişim | İnternete açık MOVEit web arayüzündeki kimlik doğrulamasız SQLi | Belirli MOVEit endpoint'lerine olağan dışı istekler |
| Kalıcılık | `human2.aspx` adlı web shell (LEMURLOOT) yerleştirildi | `wwwroot` altında yeni `.aspx` dosyası, IIS işçi sürecinin dosya yazması |
| Toplama | Web shell üzerinden dosya ve DB içeriği listelendi | Web shell'e özel header ile gelen istekler |
| Sızdırma | Büyük hacimli dosya indirimi | Sunucudan dışarı anormal hacimde çıkış trafiği |
| Etki | Veri gaspı (şifreleme yok, sadece extortion) | 2.700+ kurum etkilendi |

**Ders:** Tek bir SQLi → web shell → toplu veri sızıntısı. Web shell oluşumu (dosya oluşturma olayı) en güvenilir ve en geç tetiklenen alarmdır; ondan önceki aşamaları yakalamak hasarı önler.

### 2.5 Güncel CVE'ler (2025–2026)

| Yıl | Ürün / CVE | Özellik | Ders |
|---|---|---|---|
| 2026 | Drupal Core – [CVE-2026-9082](https://gbhackers.com/cisa-warns-drupal-core-sql-injection-vulnerability/amp/) | DB soyutlama API'sinde kimlik doğrulamasız SQLi; 22 Mayıs 2026 KEV | Framework kullanmak tek başına koruma değil |
| 2026 | Fortinet FortiClient EMS – [CVE-2026-21643](https://cybersecuritynews.com/fortinet-sql-injection-vulnerability-exploited/) | Kimlik doğrulamasız SQLi; 13 Nisan 2026 KEV | Yönetim sunucuları internete açılmamalı |
| 2025 | Fortinet FortiWeb – [CVE-2025-25257](https://threatprotect.qualys.com/2025/07/14/fortinet-fortiweb-unauthenticated-sql-injection-vulnerability-cve-2025-25257/) (CVSS 9.6) | Girdi `Authorization` header'ındaydı; dosya yazma ile RCE'ye ulaşıldı | Enjeksiyon noktası header olabilir; güvenlik ürününün kendisi de zafiyetli olabilir |
| 2023 | Progress MOVEit – CVE-2023-34362 | Yukarıdaki vaka | Tek SQLi = toplu veri gaspı |

---

## 03 — Tespit: log mimarisinden korelasyona

### 3.1 Tespit katmanları (defense in depth for detection)

Güvenilir SQLi tespiti dört katmandan oluşur. Her katman bir öncekinin kaçırdığını yakalar; alarm önceliği yukarıdan aşağı artar.

| Katman | Soru | Kaynak | Güven | Gecikme |
|---|---|---|---|---|
| L1 – İmza | İstekte SQL söz dizimi var mı? | Web erişim log'u, WAF | Düşük (bypass edilebilir, FP yüksek) | Anında |
| L2 – Davranış | Biri parametreyi sistematik olarak mı deniyor? | Web log istatistikleri | Orta | Dakikalar |
| L3 – Sonuç (DB) | Uygulama alışılmadık sorgu çalıştırdı mı? | DB audit log'u | Yüksek | Dakikalar |
| L4 – Etki (OS/Ağ) | Sunucuda yeni dosya / kabuk / dış bağlantı var mı? | EDR, Sysmon, auditd, firewall, DNS | **Kesin** | Saniyeler, ama saldırı ilerlemiş demek |

### 3.2 Loglama yapılandırması — önce görünürlük

Varsayılan ayarlarla SOC SQLi'nin yarısını göremez. Kural yazmadan önce bu açıkları kapat:

#### Web sunucusu: yanıt süresi ve gerçek istemci IP'si

**Apache** (`/etc/apache2/apache2.conf`): `%D` (mikrosaniye cinsinden süre) ve proxy arkasındaysan `X-Forwarded-For`:

```apache
LogFormat "%{X-Forwarded-For}i %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\" %D" combined_plus
CustomLog ${APACHE_LOG_DIR}/access.log combined_plus
```

**Nginx** (`nginx.conf`, `http {}` bloğu):

```nginx
log_format combined_plus '$remote_addr - $remote_user [$time_local] "$request" '
                         '$status $body_bytes_sent "$http_referer" "$http_user_agent" '
                         'rt=$request_time xff="$http_x_forwarded_for"';
access_log /var/log/nginx/access.log combined_plus;
```

**IIS:** Logging → Select Fields → `time-taken`, `cs(User-Agent)`, `cs(Referer)`, `X-Forwarded-For` (custom field) işaretli olmalı.

#### POST gövdesi: WAF / ModSecurity audit log

Erişim log'u POST gövdesini yazmaz. Gövdeyi görmek için ModSecurity audit log'u (`/etc/modsecurity/modsecurity.conf`):

```apache
SecRuleEngine DetectionOnly          # önce izleme modunda başla, FP'leri ayıkla, sonra On
SecAuditEngine RelevantOnly          # sadece kural tetikleyen istekleri yaz
SecAuditLogParts ABIJDEFHZ           # B: istek header'ları, I: gövde, H: tetiklenen kurallar
SecAuditLogType Serial
SecAuditLogFormat JSON               # SIEM'de ayrıştırması kolay
SecAuditLog /var/log/apache2/modsec_audit.log
```

OWASP CRS'te SQLi kuralları **942xxx** aralığındadır (ör. 942100 libinjection tabanlı tespit). Gövdede parola gibi hassas alanlar olacağı için audit log'a erişimi kısıtla ve gerekirse `SecAuditLogParts`'tan `I`'yı sadece belirli endpoint'ler için aç.

#### Veritabanı audit log'u

| DB | Yapılandırma | Neyi izle |
|---|---|---|
| MySQL 8 / Percona / MariaDB | `audit_log` eklentisi (Enterprise/Percona) veya MariaDB `server_audit`; geliştirmede `general_log` | Uygulama hesabının `information_schema` sorguları, `FILE` işlemleri, hata oranı |
| MSSQL | SQL Server Audit veya Extended Events (`sql_batch_completed`, `error_reported`) | `sys.objects`/`INFORMATION_SCHEMA` erişimi, `xp_cmdshell` çağrısı, `sp_configure` değişikliği, error 102/105/245 artışı |
| PostgreSQL | `pgaudit` (`pgaudit.log = 'read,ddl,role'`), `log_min_error_statement = error` | `pg_catalog`/`information_schema` okuma, syntax error (SQLSTATE 42601) artışı |
| Oracle | Unified Auditing | `ALL_TABLES`/`DBA_*` okuma, `UTL_HTTP` kullanımı |

**Performans uyarısı:** Tüm sorguları loglamak üretimde pahalıdır. Pratik yaklaşım: uygulama hesabı için **sadece meta tablo erişimi, hatalar, DDL ve yetki değişiklikleri**.

#### Uç nokta

- **Windows (Sysmon):** Event ID 1 (process create), 11 (file create), 3 (network connection), 22 (DNS query). Web dizinleri ve DB servis süreçleri için kural seti (ör. [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) veya [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)).
- **Linux (auditd):**

```bash
# Web dizinine yazma
-w /var/www/ -p wa -k webroot_write
# Web/DB servisinin kabuk çalıştırması
-a always,exit -F arch=b64 -S execve -F euid=33 -k www_exec      # www-data
-a always,exit -F arch=b64 -S execve -F euid=27 -k mysql_exec    # mysql (dağıtıma göre UID değişir: id mysql)
```

### 3.3 Log analizi: örnek bir saldırının izini okumak

[`ornek.log`](ornek.log) dosyasındaki access bölümü, lab'da üretilmiş tipik bir saldırı zincirini içerir. Bir analistin okuma sırası:

1. **Kim?** Tek kaynak IP (`203.0.113.45`) dakikalar içinde aynı endpoint'e (`/products.php`) yüzlerce istek atıyor.
2. **Ne ile?** User-Agent önce araç adını taşıyor, sonra tarayıcı taklidine dönüyor → otomasyon + gizlenme çabası.
3. **Nasıl gelişti?** Önce `500` yanıtları (probe), sonra iki farklı yanıt boyutu arasında gidip gelme (boolean blind), sonra yanıt süresi kümelenmesi (time-based), en sonda tek bir **çok büyük `200` yanıtı** (veri çıkarma).
4. **Sonuç?** Büyük yanıttan dakikalar sonra aynı IP'den daha önce hiç var olmayan bir dosyaya (`/uploads/x.php`) istek → **web shell şüphesi, kritik**.

Bu okuma sırası (kim → ne ile → nasıl → sonuç) tüm web saldırılarında aynıdır ve aşağıdaki sorgular bu adımları otomatikleştirir.

**`ornek.log` satırlarında beklenen kurallar:**

| Dosya | İçerik | Beklenen Wazuh kuralı |
|---|---|---|
| access satır 2 | Tırnaklı probe, araç UA, 500 | 100101 |
| access satır 5–6 | Koşullu gecikme, ~5 sn yanıt (son alan mikrosaniye) | 100100 |
| access satır 7 | Meta tablo sorgusu, 200 | 100100 → **100102** |
| access satır 8 | Büyük yanıt (184 KB) — veri çıkarma | 100102 · Splunk `06` |
| access satır 9 | Daha önce olmayan betik dosyasına istek | Splunk/FIM korelasyonu (100121) |
| access satır 10 | Engellenmiş tarayıcı denemesi, 403 | 100100 (deneme) |
| modsec satır 1 | CRS 942100 **Warning** (engellenmedi) | 100110 → **100111** |
| modsec satır 2 | CRS 942100 Access denied 403 | 100110 |

### 3.4 Splunk

Tüm sorgular [`splunk.spl`](splunk.spl) dosyasında numaralı bölümler halinde duruyor. Burada ne yaptıkları ve nasıl ayarlanacakları:

| # | Katman | Ne yakalar | Önerilen kullanım |
|---|---|---|---|
| 01 | L1 | Decode + lowercase sonrası SQL anahtar kelime/fonksiyon kalıpları | Avcılık, saatlik alert |
| 02 | L1 | Araç User-Agent'ları ve yüksek hacim | 15 dk'lık alert, otomatik engelleme tetikleyicisi |
| 03 | L2 | Tek parametreye çok sayıda varyant, az sayıda yanıt boyutu | 5 dk'lık alert |
| 04 | L2 | Yanıt sürelerinin dar bir aralıkta kümelenmesi | 15 dk'lık alert |
| 05 | L2 | IP/endpoint başına 500 hatası patlaması (probe aşaması) | 5 dk'lık alert |
| 06 | L2/L3 | Endpoint'in normalinden çok büyük 200 yanıtı + SQL kalıbı | **Yüksek öncelikli** alert |
| 07 | L1 | CRS 942xxx kurallarının tetiklenmesi, engellenen/geçen ayrımı | Dashboard + alert |
| 08 | L3 | MSSQL'de meta tablo erişimi, `xp_cmdshell`, yapılandırma değişikliği | Kritik alert |
| 09 | L3 | DB tarafında syntax error patlaması | 10 dk'lık alert |
| 10 | L4 | Web/DB servisinin kabuk açması, web dizininde yeni betik | **Kritik** alert |
| 11 | Hepsi | Risk tabanlı puanlama: IP başına katmanların toplamı | Ana notable/korelasyon |
| 12 | — | Saldırgan IP'ler, hedef endpoint'ler, zaman çizelgesi | SOC dashboard |

#### Sorgu yazarken uyulan prensipler

- **Normalize et, sonra eşleştir.** `urldecode()` iki kez (çift kodlama), `lower()`, yorum ve boşluk karakterlerini tek boşluğa indir. Ham `uri` üzerinde regex, kodlanmış payload'ları kaçırır.
- **Kategoriye bak.** Tek kelime (`select`) yerine kategori (meta tablo erişimi, gecikme fonksiyonları, UNION yapısı) arayan regex daha az FP verir.
- **`tstats` ile hızlandır.** Data model (CIM `Web`) kullanılıyorsa davranışsal sorguları `| tstats count from datamodel=Web where ... by Web.src Web.url` ile çalıştır; ham aramadan 10–100 kat hızlıdır.
- **Baseline ile karşılaştır.** Sabit eşik (`count > 100`) yerine endpoint'in kendi geçmişine göre `eventstats`/`streamstats` ile z-skoru.

#### Risk tabanlı alarm (RBA) mantığı

Tek bir imza eşleşmesi analisti yormamalı. Her katman `risk_object=src` üzerine puan yazar; toplam eşiği geçen IP notable olur:

| Olay | Risk puanı |
|---|---|
| İmza eşleşmesi (403 ile engellenmiş) | +10 |
| İmza eşleşmesi (200 ile geçmiş) | +25 |
| Otomatik araç | +30 |
| Blind / time-based davranış | +40 |
| 500 hata patlaması | +20 |
| Yanıt boyutu anomalisi + SQL kalıbı | +60 |
| DB meta tablo erişimi (uygulama hesabı) | +70 |
| Web shell / kabuk süreci | +100 |

**Eşik:** 24 saatte ≥ 100 → *Notable: Olası başarılı SQL Injection*. Böylece yalnızca 403 alan tarayıcılar sessizce birikir; sonuca ulaşan saldırgan hemen yükselir.

### 3.5 Wazuh

Tüm kurallar ve ayarlar [`wazuh.xml`](wazuh.xml) dosyasında.

#### Yerleşik kurallar

Wazuh, web log'ları için `0245-web_rules.xml` ile gelir. SQLi ile ilgili başlıcaları: **31103** (SQL injection girişimi), **31106** (web saldırısı 200 ile döndü), **31152** (aynı kaynaktan çoklu SQLi). Seviye ve açıklamalar sürüme göre değişebilir; kendi sürümünü doğrula:

```bash
grep -n -A6 'id="31103"\|id="31106"\|id="31152"' /var/ossec/ruleset/rules/0245-web_rules.xml
```

#### Özel kural seti (100100–100199)

| ID | Seviye | Mantık | Aktif yanıt |
|---|---|---|---|
| 100100 | 8 | Gelişmiş imza (kodlanmış hâller dahil) | — |
| 100101 | 10 | Otomatik araç User-Agent'ı | firewall-drop 30 dk |
| 100102 | 12 | İmza eşleşen istek 200 döndü | Yok — analiste / SOAR'a |
| 100103 | 12 | 2 dk'da aynı IP'den 15+ imza (frekans) | firewall-drop 30 dk |
| 100104 | 10 | 1 dk'da aynı IP'den 20+ HTTP 500 | — |
| 100110 | 9 | ModSecurity CRS 942xxx tetiklendi | — |
| 100111 | 12 | ModSecurity SQLi tetiklendi ama istek engellenmedi (DetectionOnly / yanlış ayar) | — |
| 100120 | 14 | Linux: `www-data`/`mysql` kullanıcısı kabuk çalıştırdı (auditd) | Analiste / izolasyon |
| 100121 | 13 | Web dizinine betik dosyası yazıldı (auditd / FIM) | — |
| 100130 | 14 | Windows: `w3wp.exe`/`sqlservr.exe` alt süreci `cmd`/`powershell` (Sysmon) | Analiste / izolasyon |

**Neden başarı kurallarında otomatik engelleme yok?** Başarılı bir saldırıda IP engellemek hasarı geri almaz, üstelik saldırgan zaten web shell ile farklı IP'den gelebilir. Bu alarmlar insana (veya onaylı SOAR playbook'una) gitmeli: *Otomatik engelleme taramaya, analiz insana.*

#### Test etme

```bash
/var/ossec/bin/wazuh-logtest
# ornek.log içinden "#" ile başlamayan bir satır yapıştır.
# Phase 3 çıktısında beklenen rule id ve level'ı gör.
```

FIM (File Integrity Monitoring) ile web dizinini gerçek zamanlı izlemek için agent `ossec.conf`:

```xml
<syscheck>
  <directories realtime="yes" check_all="yes" report_changes="no">/var/www/html</directories>
  <directories realtime="yes" check_all="yes">C:\inetpub\wwwroot</directories>
</syscheck>
```

### 3.6 Ağ tarafı: PCAP ve Zeek ile doğrulama

SIEM alarmı sonrası, elinde trafik kaydı varsa doğrulama için:

**Wireshark görüntüleme filtreleri:**

```
http.request.uri contains "union" || http.request.uri contains "information_schema"
http.request and ip.src == 203.0.113.45
http.response.code == 500
http.time > 4                                   # yavaş yanıtlar (time-based)
dns && ip.src == <DB_SUNUCU_IP>                 # DB'den dışarı DNS (OOB)
```

*Statistics → HTTP → Requests* ile endpoint başına istek sayısını; *Follow → HTTP Stream* ile büyük yanıtın içeriğini (hangi verinin çıktığını) gör.

**Zeek `http.log`:** `zeek-cut ts id.orig_h method host uri status_code response_body_len user_agent < http.log` ile alanları çıkar; yanıt boyutu ve URI kalıpları için Splunk'taki mantığın aynısı uygulanır. DB sunucusunun `dns.log` ve `conn.log` kayıtlarında dış hedef olmamalı.

### 3.7 Yanlış pozitif yönetimi

| FP kaynağı | Belirti | Çözüm |
|---|---|---|
| İç zafiyet tarayıcıları (Nessus, Acunetix, Burp Enterprise, ZAP) | Planlı zamanlarda yüksek hacim | `lookup` ile tarayıcı IP allowlist'i + tarama takvimi |
| Arama kutusu | Kullanıcı "select" veya "union" kelimesi arıyor | Regex'i tek kelime yerine yapıya göre yaz; arama endpoint'i için eşiği yükselt |
| İçerik yönetim / raporlama ekranları | Meşru SQL benzeri parametreler (filtre ifadeleri) | Endpoint bazlı istisna, ama sadece yetkili oturumlar için |
| Pentest / bug bounty | Duyurulmuş test pencereleri | Değişiklik kaydı + geçici istisna, bitince geri al |
| Tırnak içeren isimler | `O'Brien` gibi soyadlar | Tek başına `'` kural tetiklememeli; en az bir SQL yapısıyla birlikte aranmalı |

**Kural sağlığı metrikleri:** Her kural için aylık *tetiklenme sayısı*, *gerçek pozitif oranı*, *ortalama triyaj süresi* takip edilmeli. TP oranı %5'in altındaki kural ya ayarlanır ya da RBA'ya (puan katkısına) indirilir.

---

## 04 — Önleme, sertleştirme ve olay müdahalesi

### 4.1 Tek gerçek çözüm: parametreli sorgu

Prepared statement'ta sorgu yapısı önce derlenir, değer sonra yalnızca veri olarak bağlanır (bkz. [§1.1](#11-kök-neden-kod-ile-verinin-karışması)). Diğer tüm katmanlar zararı sınırlar.

```php
// PHP – PDO (emulation kapalı: gerçek server-side prepare)
$pdo = new PDO($dsn, $u, $p, [PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$st = $pdo->prepare('SELECT id, role FROM users WHERE username = ?');
$st->execute([$username]);
```

```java
// Java – JDBC
try (PreparedStatement ps = conn.prepareStatement("SELECT id, role FROM users WHERE username = ?")) {
    ps.setString(1, username);
    try (ResultSet rs = ps.executeQuery()) { /* ... */ }
}
// JPA/Hibernate: string birleştirme YOK, named parameter VAR
em.createQuery("FROM User u WHERE u.username = :u", User.class).setParameter("u", username);
```

```python
# Python – DB-API (psycopg, sqlite3, mysqlclient)
cur.execute("SELECT id, role FROM users WHERE username = %s", (username,))
# SQLAlchemy
session.execute(text("SELECT id FROM users WHERE username = :u"), {"u": username})
```

```csharp
// C# – ADO.NET / Dapper / EF Core
var cmd = new SqlCommand("SELECT id FROM users WHERE username = @u", conn);
cmd.Parameters.Add("@u", SqlDbType.NVarChar, 64).Value = username;
// EF Core: FromSqlInterpolated parametreler; FromSqlRaw + string birleştirme TEHLİKELİ
ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Username = {username}");
```

```javascript
// Node.js – mysql2 / pg
await pool.execute('SELECT id FROM users WHERE username = ?', [username]);   // mysql2
await client.query('SELECT id FROM users WHERE username = $1', [username]);  // pg
```

```go
// Go – database/sql
row := db.QueryRowContext(ctx, "SELECT id FROM users WHERE username = $1", username)
```

#### Parametreleştirilemeyen yerler: allowlist

Tablo/kolon adı, `ORDER BY` kolonu ve sıralama yönü yer tutucu olamaz. Kullanıcı girdisini **sabit bir eşleme tablosuna** çevir; girdinin kendisi asla sorguya girmesin:

```python
SIRALANABILIR = {"ad": "name", "tarih": "created_at", "fiyat": "price"}
kolon = SIRALANABILIR.get(req.args.get("sort"), "created_at")
yon = "DESC" if req.args.get("dir") == "desc" else "ASC"
cur.execute(f"SELECT * FROM products ORDER BY {kolon} {yon} LIMIT %s", (limit,))
```

#### ORM ve framework tuzakları

| Framework | Tehlikeli kullanım | Güvenli karşılığı |
|---|---|---|
| Django | `.raw(f"... {x}")`, `.extra(where=[...])`, `RawSQL` | ORM filtreleri, `.raw(sql, [params])` |
| Laravel | `DB::raw()`, `whereRaw("id = $x")`, `orderByRaw($x)` | `whereRaw('id = ?', [$x])`, allowlist |
| Sequelize | `sequelize.literal(x)`, `query()` ile birleştirme | `replacements` / `bind` |
| Hibernate | HQL/JPQL string birleştirme | `setParameter` |
| Stored procedure | İçeride `EXEC(@sql)` / `EXECUTE IMMEDIATE` birleştirme | `sp_executesql` + parametre |

**Yetersiz yöntemler:** Sadece tırnak kaçırma (`addslashes`, manuel escape) sayısal bağlamda ve karakter seti farklılıklarında işe yaramaz; kelime silen blacklist filtreleri atlatılır; client-side doğrulama hiçbir şey sağlamaz.

### 4.2 Katmanlı savunma kontrol listesi

| Katman | Kontrol | Etkisi |
|---|---|---|
| Kod | Parametreli sorgu, ORM'de raw'dan kaçınma | Kök nedeni kapatır |
| Kod incelemesi | SAST: [Semgrep](https://semgrep.dev/r?q=sqli), CodeQL (`js/sql-injection`, `java/sql-injection`), SonarQube | Hatalı kalıbı merge öncesi yakalar |
| Girdi | Tip doğrulama (id = tamsayı), uzunluk sınırı, şema doğrulama (JSON Schema) | Saldırı yüzeyini daraltır |
| DB hesabı | Uygulama hesabı DBA/sa/root **değil**; sadece gerekli tablolarda gerekli yetkiler; okuma ve yazma için ayrı hesaplar | Veri dökümünü ve OS'a geçişi sınırlar |
| DB sertleştirme | MySQL: `FILE` yetkisi yok, `secure_file_priv` ayarlı · MSSQL: `xp_cmdshell` kapalı, `Ad Hoc Distributed Queries` kapalı · PostgreSQL: `pg_execute_server_program`/`pg_read_server_files` rolü yok · Oracle: `UTL_HTTP`/`UTL_INADDR` PUBLIC'ten alınmış | RCE ve OOB yollarını kapatır |
| Hata yönetimi | Kullanıcıya genel hata sayfası, ayrıntı yalnızca sunucu log'una | Error-based sızıntıyı keser |
| Veri | Parolalar Argon2id/bcrypt; hassas kolonlar şifreli (TDE + kolon şifreleme) | Sızıntının etkisini azaltır |
| Ağ | DB sunucusundan internete çıkış **yok** (egress deny); DB portu sadece uygulama sunucusundan | OOB ve reverse shell'i keser |
| WAF | ModSecurity + OWASP CRS, paranoia level 2+, önce DetectionOnly ile ayar | Otomatik taramaları azaltır (tek savunma değil!) |
| Test | DAST (OWASP ZAP, Burp Scanner), yıllık pentest, bug bounty | Kaçanı bulur |
| Ürün yönetimi | İnternete açık ürünler için envanter + CISA KEV takibi + acil yama süreci | 2023–2026 olaylarının çoğunu önlerdi |

#### WAF ayarı (OWASP CRS)

- **Paranoia Level:** PL1 düşük FP, PL2 bankacılık/kritik uygulamalar için önerilen başlangıç, PL3–4 yüksek FP ile sıkı.
- **Anomaly scoring:** CRS her eşleşmeye puan verir, `inbound_anomaly_score_threshold` (varsayılan 5) aşılınca engeller. Ayar sürecinde eşiği yüksek tutup log'ları incele, sonra düşür.
- **İstisnalar:** Kural kapatmak yerine `SecRuleUpdateTargetById` ile sadece ilgili parametreyi hariç tut.
- **Virtual patching:** Yama gelene kadar zafiyetli endpoint/parametre için özel engelleme kuralı — olay müdahalesinin ilk saatlerinde kritik.

### 4.3 Olay müdahale playbook'u (NIST SP 800-61 r2)

#### Triyaj karar ağacı

```
Alarm geldi
 ├─ Kaynak iç tarayıcı / onaylı pentest mi? ── Evet → kapat (FP), allowlist'i doğrula
 └─ Hayır
     ├─ Tüm istekler 403/404 ve yanıt boyutları normal mi? ── Evet → DENEME (P3)
     │                                                          IP engelle, WAF kuralını doğrula, kapat
     └─ Hayır: 200 + anormal boyut / DB meta sorgusu / yeni dosya / kabuk süreci
         └─ OLASI BAŞARI (P1) → L2 + IR ekibine eskale, aşağıdaki adımlar
```

#### P1 adımları

| # | Aşama | Aksiyon | Sorumlu | Hedef süre |
|---|---|---|---|---|
| 1 | Tespit & analiz | Alarmı doğrula, kapsamı çıkar: tüm saldırgan IP'leri (UA, kalıp, zaman ile birleştir), etkilenen endpoint'ler, ilk ve son başarılı istek | L1 → L2 | 30 dk |
| 2 | Delil koruma | Web/WAF/DB/OS log'larını değiştirilemez depoya kopyala; gerekiyorsa disk ve bellek imajı **değişiklikten önce** | L2 / DFIR | 1 sa |
| 3 | Kontrol altına alma | Endpoint için virtual patch veya geçici kapatma; uygulama DB hesabının parolasını döndür; web shell varsa sunucuyu EDR ile izole et | L2 + uygulama ekibi | 1 sa |
| 4 | Etki analizi | DB audit'ten hangi tablolardan ne kadar veri okunduğunu çıkar; kişisel veri var mı? | DFIR + DB ekibi | 24 sa |
| 5 | Temizleme | Kodu düzelt veya ürün yamasını uygula; aynı kalıbı tüm kod tabanında ara (SAST); web shell, eklenen kullanıcılar, zamanlanmış görevler, değiştirilmiş prosedürleri kaldır | Uygulama + sistem | 48 sa |
| 6 | Kimlik bilgisi rotasyonu | DB hesapları, uygulama sırları (API key, JWT secret), etkilenen kullanıcı parolaları | IAM | 48 sa |
| 7 | Kurtarma | Temiz kaynaktan yeniden yayın; 30 gün yükseltilmiş izleme (aynı endpoint, aynı IoC'ler) | Ops + SOC | — |
| 8 | Yasal bildirim | Kişisel veri sızdıysa KVKK m.12 uyarınca Kurul'a **72 saat** içinde bildirim, ilgili kişilere bildirim; bankacılıkta BDDK düzenlemeleri ve kurum içi olay bildirim prosedürü | Hukuk + CISO | 72 sa |
| 9 | Öğrenilen dersler | Kök neden analizi; kaçırılan tespiti kurala ekle; geliştirici eğitimi; kural sağlık metriklerini güncelle | Tüm ekipler | 2 hafta |

#### Analist ticket şablonu

```
Başlık     : [P1] Olası başarılı SQL Injection - <endpoint> - <kaynak IP>
Tetikleyen : Wazuh 100102 / Splunk RBA risk=<puan>
Zaman      : İlk probe <ts> · İlk başarılı istek <ts> · Son istek <ts>
Kaynak     : <IP listesi>, ülke, ASN, itibar (AbuseIPDB / VirusTotal / GreyNoise)
Hedef      : <host> <endpoint> <parametre>
Gözlem     : <yanıt boyutu anomalisi, DB meta sorgusu, yeni dosya, süreç>
Etki       : <okunan tablolar, kayıt sayısı tahmini, kişisel veri: evet/hayır>
Aksiyonlar : <engelleme, virtual patch, parola rotasyonu, izolasyon>
Sonraki    : <bekleyen işler, sorumlular>
```

### 4.4 SOAR otomasyonu (Shuffle)

Wazuh → Shuffle akışı, deneme/başarı ayrımını otomatikleştirip analistin önüne zenginleştirilmiş vaka koyar:

1. **Tetik:** Wazuh integration (`<integration><name>shuffle</name><hook_url>...</hook_url><rule_id>100101,100102,100103,100120,100121,100130</rule_id></integration>`).
2. **Zenginleştirme:** Kaynak IP için AbuseIPDB + VirusTotal + GreyNoise sorgusu; Splunk'tan son 24 saatteki RBA puanı.
3. **Dallanma:**
    - 100101/100103 ve itibar kötü → WAF/firewall API'si ile engelle, vaka aç (P3), otomatik kapat.
    - 100102/100120/100121/100130 → TheHive/Jira'da P1 vaka, Slack/Teams'e L2 bildirimi, **engelleme için onay butonu** (insan onayı).
4. **Kapanış:** Vakaya tüm zenginleştirme çıktısı ve ham log bağlantıları eklenir.

---

## 05 — Pratik: odalar, lab ve kaynaklar

### 5.1 Önerilen sıra

Önce saldırıyı izinli bir ortamda kendi elinle gör, sonra aynı saldırının alarmını SOC analisti olarak çöz.

| # | Platform | Oda / ders | Odak |
|---|---|---|---|
| 1 | TryHackMe | [SQL Injection](https://tryhackme.com/room/sqlinjectionlm) | Türler ve mekanizma |
| 2 | TryHackMe | [SQLMap: The Basics](https://tryhackme.com/r/room/sqlmap) | Otomasyon ve araç izleri (tespit için önemli) |
| 3 | TryHackMe | [Advanced SQL Injection](https://tryhackme.com/room/advancedsqlinjection) | Second-order, OOB, filtre atlatma |
| 4 | TryHackMe | [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop) | Gerçekçi uygulamada SQLi |
| 5 | PortSwigger | [Web Security Academy – SQL injection](https://portswigger.net/web-security/sql-injection) | Ücretsiz, DB'ye göre ayrılmış lab'lar |
| 6 | LetsDefend | [Web Attacks 101](https://app.letsdefend.io/training/lessons/web-attacks-101) | Web log'undan SQLi tespiti |
| 7 | LetsDefend | Monitoring → **SOC165 – Possible SQL Injection Payload Detected** ([örnek çözüm](https://zendannyy.substack.com/p/lets-defend-write-up)) | Gerçek ticket akışı: triyaj, log yönetimi, kapatma |
| 8 | LetsDefend | [How to Detect SQL Injection](https://letsdefend.io/blog/how-to-detect-sql-injection) | Analist özeti |

### 5.2 Kendi detection lab'ın

Bu repodaki kuralları uçtan uca denemek için:

```
[Kali / saldırgan VM] ──HTTP──> [Ubuntu: Apache + ModSecurity + DVWA/Juice Shop + MySQL]
                                      │  Wazuh agent (access/error/audit log + FIM + auditd)
                                      │  Splunk Universal Forwarder
                                      ▼
                          [Wazuh manager]     [Splunk (Free/Dev lisansı)]
```

1. Hedef: Ubuntu 24.04, `apt install apache2 libapache2-mod-security2 modsecurity-crs mariadb-server php`, üzerine [DVWA](https://github.com/digininja/DVWA).
2. [§3.2](#32-loglama-yapılandırması--önce-görünürlük)'deki log formatlarını ve auditd kurallarını uygula.
3. Wazuh agent'a [`wazuh.xml`](wazuh.xml) Bölüm C, manager'a Bölüm A ve Bölüm B.
4. Splunk UF ile `/var/log/apache2/` → `index=web`.
5. DVWA SQLi modülünü "low" seviyede çalıştır; her aşamada hangi kuralın tetiklendiğini bir tabloya not et. Sonra "medium/high" seviyede tekrar et ve **hangi kuralların kaçırdığını** bul — detection engineering'in özü budur.
6. Kuralları [`ornek.log`](ornek.log) ile `wazuh-logtest` üzerinden de doğrula.

### 5.3 Kendini test et

1. Erişim log'unda hiçbir SQLi imzası görmediğin halde DB'de meta tablo sorguları görüyorsan saldırı muhtemelen nereden geliyordur?
2. Boolean blind saldırıyı imzasız nasıl yakalarsın? Hangi iki metriği birlikte kullanırsın?
3. Neden 100102 kuralına otomatik IP engelleme bağlamadık?
4. Uygulama hesabı `SELECT`-only olsaydı MOVEit vakasındaki hangi aşama gerçekleşemezdi?
5. CRS `DetectionOnly` modunda çalışıyorsa hangi kural (100110 / 100111) ne zaman tetiklenir ve neden ikincisi daha yüksek seviyededir?

<details><summary>Cevaplar</summary>

1. POST gövdesi, JSON API, header veya cookie (erişim log'u bunları yazmaz) — ya da second-order.
2. Aynı endpoint'e kısa sürede çok sayıda farklı sorgu varyantı **ve** çok az sayıda farklı yanıt boyutu (`splunk.spl` → 03).
3. Başarılı saldırıda engelleme hasarı geri almaz, saldırgan web shell ile başka IP'den döner; ayrıca yanlış engelleme meşru trafiği keser. Karar insana / onaylı SOAR'a ait.
4. Dosya yazarak web shell yerleştirme (kalıcılık) — veri okuma yine mümkün olurdu.
5. 100110 her CRS SQLi tetiklenmesinde; 100111 istek **engellenmediğinde** (Warning). İkincisi saldırının uygulamaya ulaştığını gösterir.

</details>

### 5.4 Kaynaklar

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Query Parameterization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html)
- [MITRE CWE-89](https://cwe.mitre.org/data/definitions/89.html) · [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/) · [T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [OWASP Core Rule Set](https://coreruleset.org/)
- [Wazuh PoC: Detecting SQL injection](https://documentation.wazuh.com/current/proof-of-concept-guide/detect-web-attack-sql-injection.html)
- [Splunk Security Content (ESCU)](https://research.splunk.com/) — "SQL Injection" araması
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA AA23-158A – Cl0p / MOVEit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a)
- Güncel CVE kaynakları: [CVE-2026-9082 (Drupal)](https://gbhackers.com/cisa-warns-drupal-core-sql-injection-vulnerability/amp/) · [CVE-2026-21643 (FortiClient EMS)](https://cybersecuritynews.com/fortinet-sql-injection-vulnerability-exploited/) · [CVE-2025-25257 (FortiWeb)](https://threatprotect.qualys.com/2025/07/14/fortinet-fortiweb-unauthenticated-sql-injection-vulnerability-cve-2025-25257/)
