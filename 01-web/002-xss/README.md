# #002 — Cross-Site Scripting (XSS)

> Saldırganın kontrol ettiği verinin bir web sayfasına **metin olarak değil, çalıştırılabilir betik olarak** girmesi ve kurbanın tarayıcısında, kurbanın oturum yetkileriyle çalışması. 2025–2026'da Exchange OWA (CVE-2026-42897), Roundcube (CVE-2025-68461), Zimbra (CVE-2025-27915) ve MDaemon (CVE-2024-11182) XSS'leri CISA KEV listesine girdi; APT28'e atfedilen *Operation RoundPress* kampanyası yalnızca bir e-postayı açtırarak devlet kurumlarının posta kutularını boşalttı.

## Özet kartı

| Alan | Değer |
|---|---|
| Kategori | Web uygulama saldırıları (Web #2) — istemci tarafı enjeksiyon |
| OWASP Top 10 (2021) | A03:2021 – Injection (XSS 2021'de bu başlığa katıldı) |
| CWE | CWE-79 (XSS), CWE-80 (basit script tag), CWE-83 (attribute içinde betik), CWE-87 (alternatif XSS söz dizimi), CWE-116 (yanlış kodlama) |
| CAPEC | CAPEC-63 (XSS), CAPEC-591 (Reflected), CAPEC-592 (Stored), CAPEC-588 (DOM-based) |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application · T1189 Drive-by Compromise · T1539 Steal Web Session Cookie · T1185 Browser Session Hijacking · T1114.002/.003 Remote Email Collection / Email Forwarding Rule · T1056.003 Web Portal Capture · T1566 Phishing (taşıyıcı) |
| Etki (CIA) | **C:** oturum, posta, kişi listesi, kimlik bilgisi çalma · **I:** kurban adına işlem (parola/MFA değiştirme, yönlendirme kuralı, admin oluşturma) · **A:** genelde düşük (sayfa bozma) |
| Tipik CVSS 3.1 | 5.4 – 8.1 (`AV:N/AC:L/PR:N/UI:R/S:C` — kullanıcı etkileşimi gerekir; stored + yönetici paneli → yüksek) |
| Saldırgan seviyesi | Tarayıcı/araç (Dalfox, XSStrike, Burp) → İleri (filtre atlatma, sanitizer bypass, webmail 0-day) |
| SOC önceliği | Deneme (reflected probe, 403): **Düşük** · Stored içerik / yönetici panelinde çalışma / oturum ele geçirme / posta yönlendirme kuralı: **Kritik** |
| Wazuh kural bloğu | 100200 – 100299 |

## 30 saniyede SOC özeti

1. **Ne arıyorum?** URL/gövdede `<script`, `on…=` olay işleyicileri, `javascript:` URI'leri, HTML entity/URL kodlu açılı parantez; User-Agent'ta XSS tarayıcı adları; CSP ihlal raporlarında yabancı betik kaynakları.
2. **Deneme mi, başarı mı?** Reflected probe'lar ve 403'ler denemedir. **Başarı belirtileri:** içerik kaydeden bir endpoint'e (yorum, ticket, profil, e-posta) giden ve engellenmeyen istek + o sayfayı açan kullanıcıların tarayıcısından yabancı alan adına istek, CSP `report-only` ihlali, aynı oturum çerezinin yeni IP'den kullanılması, kurbanın hesabında yeni posta yönlendirme kuralı veya parola/MFA değişikliği.
3. **İlk aksiyon?** Deneme → IP'yi engelle, WAF kuralını doğrula, kapat. Başarı → zararlı içeriği kaldır/karantinaya al, etkilenen kullanıcıların oturumlarını sonlandır, yönlendirme kurallarını sil, parola/MFA sıfırla, L2/IR'a eskale et.

## İçindekiler

1. [Teori: XSS nasıl çalışır?](#01--teori-xss-nasıl-çalışır)
2. [Saldırı akışı ve her aşamanın izi](#02--saldırı-akışı-ve-her-aşamanın-izi)
3. [Tespit: sunucu, tarayıcı ve kimlik katmanları](#03--tespit-sunucu-tarayıcı-ve-kimlik-katmanları)
4. [Önleme, sertleştirme ve olay müdahalesi](#04--önleme-sertleştirme-ve-olay-müdahalesi)
5. [Pratik: odalar, lab ve kaynaklar](#05--pratik-odalar-lab-ve-kaynaklar)

**Bu klasördeki diğer dosyalar (kopyala-yapıştır için):**

| Dosya | İçerik |
|---|---|
| [`splunk.spl`](splunk.spl) | 12 SPL sorgusu, numaralı bölümler halinde |
| [`wazuh.xml`](wazuh.xml) | Özel kurallar (100200–100299) + aktif yanıt + agent ayarları |
| [`ornek.log`](ornek.log) | Access, ModSecurity, CSP raporu ve Microsoft 365 audit test satırları |

## 01 — Teori: XSS nasıl çalışır?

### 1.1 Kök neden: veri, yanlış bağlamda kod olarak yorumlanır

Sunucu tarayıcıya tek bir metin gönderir: HTML. Bu metnin içinde **yapı** (etiketler, attribute'lar, betik blokları) ve **veri** (kullanıcı adı, yorum, arama terimi) iç içedir. Tarayıcının ayrıştırıcısı hangi karakterin geliştiriciden, hangisinin kullanıcıdan geldiğini bilemez. Kullanıcı verisi, bulunduğu **bağlamın** söz dizimine ait karakterleri (ör. `<`, `"`, `'`, `` ` ``, `:`) kodlanmadan taşıyorsa, verinin sınırı aşılır ve tarayıcı onu yapı — sonunda da JavaScript — olarak çalıştırır.

SQLi'den (#001) temel farkı: **kurban sunucu değil, kullanıcının tarayıcısıdır.** Sunucu sadece taşıyıcıdır; zararlı kod, kurbanın oturumu ve yetkileriyle, uygulamanın kendi kökeninde (origin) çalışır.

#### Neden bu kadar güçlü? Same-Origin Policy

Tarayıcı, bir kökenden (şema + alan adı + port) gelen betiğin başka bir kökenin verisine erişmesini engeller. XSS bu duvarı **aşmaz, içeriden başlar**: betik, hedef uygulamanın kendi sayfasında çalıştığı için o kökenin çerezlerine (HttpOnly değilse), DOM'una, localStorage'ına ve aynı kökene yapılan kimlik doğrulamalı isteklere tam erişimi vardır. Bu yüzden XSS, "kurbanın klavyesine geçmek" ile eşdeğerdir.

#### Bağlam her şeydir

| Çıktı bağlamı | Örnek konum | Doğru savunma |
|---|---|---|
| HTML gövdesi | `<div>VERI</div>` | HTML entity kodlama |
| HTML attribute | `<input value="VERI">` | Attribute kodlama + **mutlaka tırnak** |
| JavaScript string | `<script>var x='VERI'</script>` | JS string kodlama; mümkünse veriyi `data-` attribute veya JSON ile taşı |
| URL | `<a href="VERI">` | `http/https` allowlist + URL kodlama |
| CSS | `style="color:VERI"` | Kullanıcı verisini CSS'e koyma; allowlist |
| DOM sink | `el.innerHTML = VERI` | `textContent`, sanitizer (DOMPurify), Trusted Types |

HTML kodlaması yapılmış bir değer, bir JavaScript bağlamında hâlâ tehlikelidir. XSS'in "kaçış yaptım ama yine oldu" hatalarının çoğu **yanlış bağlam için kodlama** hatasıdır (CWE-116).

### 1.2 XSS türleri — betik nereye kaydedilir ve nerede çalışır?

| Tür | Mekanizma (kavramsal) | Kurbanın yapması gereken | Savunucunun gördüğü iz |
|---|---|---|---|
| **Reflected** | İstekteki veri, aynı yanıtta kodlanmadan geri yansır | Hazırlanmış bir bağlantıya tıklamak | Erişim log'unda imzalı URL; referer genelde e-posta/sohbet/boş; aynı URL'ye birden fazla iç kullanıcıdan istek |
| **Stored (kalıcı)** | Veri DB'ye kaydedilir; sayfayı açan herkeste çalışır | Sadece sayfayı (yorum, ticket, profil, e-posta) açmak | Kaydeden `POST` (erişim log'unda gövde yok → WAF/uygulama log'u), sonra o sayfayı görüntüleyen kullanıcılardan dış istekler |
| **DOM-based** | Sunucu yanıtı temiz; istemci tarafı JS veriyi (`location.hash`, `postMessage`) tehlikeli bir sink'e yazar | Bağlantıya tıklamak | **`#` sonrası sunucuya hiç gelmez** → sunucu log'unda iz yok; sadece CSP raporu, EDR/proxy, tarayıcı telemetrisi |
| **Blind** | Stored XSS'in özel hâli: betik saldırganın göremediği bir panelde (admin, destek, log görüntüleyici) çalışır | Bir çalışanın kaydı incelemesi | Saatler/günler sonra **iç ağdan, yönetici tarayıcısından** dışarı bir geri arama (callback) |
| **Mutation (mXSS)** | Sanitizer'ın temiz bulduğu HTML, tarayıcı tarafından yeniden düzenlenince betiğe dönüşür | Sayfayı açmak | Sanitizer'dan geçmiş içerik; tespit çok zor, yama/güncel sanitizer kritik |
| **Self-XSS** | Kurban kendi tarayıcısına kodu kendisi yapıştırır (sosyal mühendislik) | Konsola yapıştırmak | Genelde log izi yok; farkındalık konusu |

**SOC için ana fikir:** Reflected türü gürültülüdür ve çoğunlukla otomatik taramadır. **Stored, blind ve webmail XSS'leri** sessizdir ama asıl hasarı yapar; tespit sunucu imzasından çok *sonuç* katmanından (tarayıcı, kimlik, posta) gelir.

### 1.3 Saldırgan XSS ile ne yapar? (etki sınıfları)

| Hedef | Kavramsal yöntem | ATT&CK | İz |
|---|---|---|---|
| Oturum çalma | Çerez/token okunup dışarı gönderilir | T1539 | Aynı oturum kimliği başka IP/UA'dan; dışarı istek |
| Oturum sürme (riding) | Betik, kurbanın oturumuyla doğrudan istek atar — çerezin dışarı çıkmasına gerek yok | T1185 | Kurbanın IP'sinden, normal dışı sıra ve hızda yönetici işlemleri |
| Kimlik bilgisi toplama | Sahte giriş formu, tarayıcı/parola yöneticisinin otomatik doldurmasını tetikleyen gizli alanlar | T1056.003 | Sayfada beklenmeyen form; dış alana POST |
| Posta toplama / yönlendirme | Webmail'de posta, kişi listesi okunur; **yönlendirme/filtre kuralı** eklenir | T1114.002, T1114.003 | Webmail/M365 audit'te yeni kural, toplu posta erişimi |
| Hesap ele geçirme | Parola, e-posta, MFA ayarı veya uygulama parolası değişimi | T1098 | Hesap değişikliği olayları, olağan dışı zamanda |
| İlk erişim / drive-by | Popüler sayfaya enjekte betik ziyaretçileri başka yere yönlendirir | T1189 | Proxy'de yeni alan adları, tarayıcı alt süreçleri |

### 1.4 Ortam ve ürün farkları

| Ortam | Neden riskli | Savunma notu |
|---|---|---|
| **Webmail** (OWA, Roundcube, Zimbra, MDaemon, Horde) | HTML e-posta = saldırganın kontrol ettiği HTML'in kurbanın oturumunda gösterilmesi; tek tık bile gerekmez | Hızlı yama, KEV takibi, mümkünse webmail'i VPN arkasına almak, posta kuralı izleme |
| Yönetici / destek panelleri | Blind XSS'in hedefi; yüksek yetkili oturum | Ayrı alan adı, sıkı CSP, iç kullanıcılar için ayrı tarayıcı profili |
| SPA (React/Angular/Vue) | Framework varsayılan olarak kodlar; tehlike "kaçış kapıları"nda ve DOM sink'lerinde | `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*` kullanımlarını SAST ile yakala |
| Markdown / zengin metin editörleri | Kullanıcının HTML yazmasına izin verilir | Güncel sanitizer, sanitizasyondan sonra içeriği değiştirmemek |
| Dosya yükleme (SVG, HTML) | SVG içinde betik olabilir; aynı kökenden sunulursa stored XSS | Yüklenen dosyaları ayrı alan adından, `Content-Disposition: attachment` ile sun |
| Log/SIEM görüntüleyicileri | Saldırgan UA veya URL'ye betik koyar; analist log'u web arayüzünde açar | SOC araçlarının kendisi de XSS hedefidir — araçları güncel tut |

### 1.5 Neden hâlâ bu kadar yaygın?

- **Bağlam çokluğu:** Tek bir "escape" fonksiyonu her bağlamı korumaz; geliştirici yanlış olanı seçer.
- **Kaçış kapıları:** Framework'ler güvenli varsayılan sunar ama "HTML göstermem lazım" ihtiyacı her projede bir `innerHTML` doğurur.
- **İstemci tarafı karmaşıklık:** DOM-based XSS sunucu tarafı taramalarda ve WAF'ta görünmez.
- **HTML e-posta:** Webmail ürünleri, saldırganın HTML'ini *tasarım gereği* göstermek zorundadır; sanitizer'daki tek bir açık doğrudan 0-day olur — RoundPress'in özü budur.
- **Yanlış önceliklendirme:** "Sadece alert kutusu çıkıyor" algısıyla düşük önem verilir; oysa gerçek dünyada XSS posta kutusu, yönetici hesabı ve kimlik bilgisi çalmanın kapısıdır.

---

## 02 — Saldırı akışı ve her aşamanın izi

> Bu bölüm saldırıyı **savunucu gözüyle** anlatır: saldırgan her aşamada neyi hedefler ve geride hangi iz kalır. Uygulamalı pratik için [§5](#05--pratik-odalar-lab-ve-kaynaklar)'teki yasal lab'ları kullan.

### 2.1 Aşamalar ve MITRE ATT&CK eşleşmesi

| # | Aşama | Saldırganın hedefi | ATT&CK | Bıraktığı iz | Tespit fırsatı |
|---|---|---|---|---|---|
| 1 | Keşif | Girdiyi yansıtan parametreleri, içerik kaydeden formları bulmak | T1595.002, T1594 | Crawler/tarayıcı UA'ları, kısa sürede çok sayıda farklı URL | Orta |
| 2 | Yansıma testi (probe) | Özel karakterlerin kodlanıp kodlanmadığını görmek | T1190 | Benzersiz bir işaret dizgisi + açılı parantez/tırnak içeren istekler; aynı parametrede sistematik varyant | **Yüksek** — en gürültülü an |
| 3 | Bağlam ve filtre analizi | Verinin hangi bağlamda yansıdığını, filtrenin neyi sildiğini anlamak | T1190 | Kodlama varyasyonları (entity, çift URL, Unicode), WAF 403 oranında artış | Yüksek |
| 4 | Teslimat | Reflected: bağlantıyı kurbana iletmek · Stored: betiği içeriğe kaydetmek · Webmail: e-posta göndermek | T1566.002, T1566.001, T1190 | Phishing e-postası, içerik kaydeden `POST`, WAF audit'te gövde eşleşmesi | Orta (posta geçidi, WAF) |
| 5 | Çalışma | Kurbanın tarayıcısında betiğin çalışması | T1189, T1059.007 | **CSP ihlal raporu**, tarayıcıdan dış alan adına istek, sayfada yabancı betik | **Yüksek** (CSP raporu varsa) |
| 6 | Toplama / sızdırma | Oturum, posta, kişi, kimlik bilgisi | T1539, T1114.002, T1056.003 | Dış alana POST/GET, webmail'de toplu posta okuma | Yüksek (proxy + uygulama log'u) |
| 7 | Kalıcılık / kötüye kullanım | Yönlendirme kuralı, uygulama parolası, MFA cihazı, yeni admin | T1114.003, T1098, T1185 | M365/webmail audit'te kural ve hesap değişikliği; çalınan oturumun yeni IP'den kullanılması | **Kesin** |

**SOC açısından anahtar fikir:** Reflected XSS'te saldırganın 2. ve 3. aşaması sunucu log'unda görünür. Stored/webmail XSS'te ise teslimat tek bir istekten/e-postadan ibarettir; asıl güvenilir sinyaller **5. aşama (tarayıcı tarafı)** ve **7. aşama (kimlik ve posta audit'i)** olur. Tespit stratejisi bu iki "geçilmesi zorunlu" noktaya yatırılmalıdır.

### 2.2 Otomatik araç izi

| Gösterge | Neden oluşur |
|---|---|
| UA'da `dalfox`, `XSStrike`, `XSSer` veya genel tarayıcı adları (`Nuclei`, `Acunetix`, `Nikto`) | Kullanıcı değiştirmezse araç kendini tanıtır |
| Aynı parametreye dakikada yüzlerce istek, her biri farklı karakter kombinasyonu | Araç bağlam ve filtre analizi yapar |
| Rastgele, benzersiz işaret dizgileri | Aracın yansımayı yanıtta bulabilmesi için |
| Çok sayıda farklı parametre adı (`?q=`, `?search=`, `?redirect=` …) | Parametre keşfi (gizli parametre avı) |
| Herkese açık OAST/geri arama servislerine yönelik alan adları içeren girdiler | Blind XSS doğrulaması — betik çalışınca araç sunucusuna geri dönüş |
| Saatler/günler sonra iç ağdan aynı geri arama alanına giden tek bir istek | Blind XSS'in **başarı anı** |

Gelişmiş saldırgan aracı değil elle hazırlanmış tek bir istek kullanır, özellikle webmail kampanyalarında hiç tarama yapmaz — bu yüzden imza katmanı tek başına yetmez.

### 2.3 Atlatma sınıfları ve kural dayanıklılığı

Hazır atlatma listelerine gerek yok; kural yazarken şu sınıflara dayanıklı olman yeterli:

| Atlatma sınıfı | Fikir | Kural tarafında karşılığı |
|---|---|---|
| Kodlama katmanları | URL, çift URL, HTML entity (ondalık/hex), Unicode, JS kaçışları | Eşleştirmeden önce **tekrar tekrar decode et**; entity kalıplarının kendisini de (`&#x3c`, `&lt`) şüpheli say |
| Etiket ve olay çeşitliliği | `script` yerine onlarca etiket ve `on…` olay işleyicisi | Tek kelimeye değil **yapıya** bak: "açılı parantez + etiket adı" ve "`on` + harfler + `=`" |
| Büyük/küçük harf, boşluk, ayraç oyunları | Etiket adında harf karıştırma, attribute arasında `/` veya satır sonu | `lower()` + boşluk/ayraç normalizasyonu, regex'te `[\s/]` |
| Protokol oyunları | `javascript:` içinde boşluk/kodlama | Şemayı normalize ederek ara; `href/src` için allowlist |
| Taşıyıcı değişimi | JSON gövdesi, header, çok parçalı form, dosya (SVG), e-posta, takvim (ICS) | Erişim log'u yetmez: WAF audit, uygulama log'u, posta geçidi ve **istemci tarafı** sinyaller |
| Sanitizer/mXSS | Ayrıştırıcı farklarından yararlanma | İmza ile yakalanamaz; sanitizer güncelliği ve CSP |

Sonuç: imza **ilk katmandır**, güven ise CSP raporlarından, dış geri aramalardan ve hesap/posta değişikliklerinden gelir.

### 2.4 Gerçek vaka zaman çizelgesi: Operation RoundPress (2023–2024)

ESET'in APT28'e orta güvenle atfettiği kampanya, webmail XSS'inin gerçek hayattaki gücünü gösterir:

| Aşama | Ne oldu | Tespit edilebilecek iz |
|---|---|---|
| Teslimat | Güncel haber/siyasi konulu hedefli e-posta; HTML gövdesine gizlenmiş betik | Posta geçidinde olağan dışı HTML yapısı, yeni gönderici alan adı |
| Çalışma | E-posta webmail'de **açıldığı anda** betik çalıştı — tıklama, yönlendirme, form yok | (Varsa) CSP ihlali; tarayıcıdan yabancı alana istek |
| Kimlik bilgisi | Gizli form alanlarıyla tarayıcı/parola yöneticisinin kayıtlı bilgileri doldurması tetiklendi | Sayfada beklenmeyen form alanları (tarayıcı/EDR telemetrisi) |
| Toplama | Posta, kişi listesi, webmail ayarları, giriş geçmişi okundu | Webmail'de kısa sürede çok sayıda API çağrısı |
| Sızdırma | Sabit kodlu C2 adresine HTTP POST | Proxy'de kullanıcı tarayıcısından yeni alana POST |
| Kalıcılık | MDaemon'da 2FA atlatma ve **uygulama parolası** ile kalıcı erişim | Hesap ayarlarında yeni uygulama parolası |
| Hedefler | Yunanistan, Ukrayna, Sırbistan, Kamerun devlet kurumları; Ukrayna/Ekvador askeri birimleri; Bulgaristan/Romanya savunma şirketleri | — |

Kullanılan zafiyetler: Roundcube **CVE-2020-35730** ve **CVE-2023-43770**, MDaemon **CVE-2024-11182** (0-day), Zimbra **CVE-2024-27443**, Horde (doğrulanmamış).

**Ders:** Webmail XSS'i bir *phishing* değil, bir **0-tık hesap ele geçirme**dir. Betiğin kalıcılığı yoktur (yalnızca e-posta açıkken çalışır), bu yüzden kalıcı iz **hesap tarafında** (uygulama parolası, yönlendirme kuralı) kalır — tespit oraya bakmalı.

İkinci örnek: 2025'te StrikeReady Labs, Zimbra **CVE-2025-27915**'in ICS takvim dosyasıyla sömürüldüğünü raporladı. Betik kimlik bilgisi, posta ve kişileri dış sunucuya gönderiyor, posta kutusuna **"Correo" adlı, iletileri dış bir adrese yönlendiren filtre kuralı** ekliyordu. Yine kalıcı iz: posta kuralı.

### 2.5 Güncel CVE'ler ve KEV kayıtları (2024–2026)

| Yıl | Ürün / CVE | Özellik | Ders |
|---|---|---|---|
| 2026 | Microsoft Exchange OWA – [CVE-2026-42897](https://www.cycognito.com/blog/emerging-threat-cve-2026-42897-microsoft-exchange-owa-cross-site-scripting-via-crafted-email/) (CVSS 8.1) | Hazırlanmış e-posta OWA'da açılınca betik çalışıyor; 14 Mayıs 2026'da 0-day olarak duyuruldu, 15 Mayıs KEV, EEMS ile otomatik geçici önlem, kalıcı yama [9 Haziran 2026](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-exchange-server-zero-day-exploited-in-attacks/amp/) | EEMS açık ve güncel olmalı; Exchange 2016/2019/SE etkilendi, Exchange Online etkilenmedi |
| 2026 | Roundcube – [CVE-2025-68461](https://cybersecuritynews.com/roundcube-vulnerabilities-exploited/) | Web arayüzünde XSS; 20 Şubat 2026'da CVE-2025-49113 (deserialization RCE) ile birlikte KEV | Webmail'de XSS ve RCE birlikte yamalanmalı |
| 2025 | Zimbra – [CVE-2025-27915](https://thehackernews.com/2025/10/zimbra-zero-day-exploited-to-target.html) | ICS takvim girdisinde stored XSS; posta yönlendirme filtresi ekleyen veri hırsızı | Takvim/ek gibi "HTML olmayan" taşıyıcılar da XSS taşır |
| 2025 | MDaemon – [CVE-2024-11182](https://cybersecuritynews.com/cisa-adds-mdaemon-email-server-xss-vulnerability/) | HTML ayrıştırıcıda XSS; RoundPress'te 0-day olarak kullanıldı, 2025'te KEV | Küçük ürünler de devlet destekli grupların hedefi |

---

## 03 — Tespit: sunucu, tarayıcı ve kimlik katmanları

### 3.1 Tespit katmanları

XSS'te kod sunucuda değil tarayıcıda çalışır; bu yüzden SQLi'deki "DB katmanı"nın yerini **tarayıcı** ve **kimlik/posta** katmanları alır.

| Katman | Soru | Kaynak | Güven | Gecikme |
|---|---|---|---|---|
| L1 – İmza | İstekte betik yapısı var mı? | Web erişim log'u, WAF (CRS 941xxx) | Düşük (bypass, FP) | Anında |
| L2 – Davranış | Biri parametreleri sistematik olarak mı deniyor? İçerik kaydeden endpoint'e imzalı veri gitti mi? | Web log istatistikleri, WAF audit (gövde) | Orta | Dakikalar |
| L3 – Tarayıcıda çalışma | Sayfada izin verilmeyen bir betik çalışmaya çalıştı mı? Kullanıcı tarayıcısı yabancı bir alana mı gitti? | **CSP ihlal raporları**, proxy/DNS, EDR tarayıcı telemetrisi | Yüksek | Saniyeler–dakikalar |
| L4 – Etki (kimlik/posta) | Oturum başka yerden kullanıldı mı? Yönlendirme kuralı, parola/MFA değişikliği oldu mu? | Uygulama oturum log'u, M365 Unified Audit, Entra ID sign-in, webmail log'u | **Kesin** | Dakikalar, ama saldırı başarılı demek |

### 3.2 Loglama yapılandırması — önce görünürlük

#### Web sunucusu ve WAF

Erişim log formatı için #001'deki `combined_plus` (yanıt süresi + `X-Forwarded-For`) yeterlidir; XSS için ek olarak **Referer** alanının kaydedildiğinden emin ol (reflected XSS bağlantısının nereden tıklandığını gösterir).

Stored XSS çoğunlukla `POST` gövdesindedir → ModSecurity audit log'u (#001 §3.2'deki `SecAuditLogParts ABIJDEFHZ`, JSON format). OWASP CRS'te XSS kuralları **941xxx** aralığındadır (ör. 941100 libinjection tabanlı XSS tespiti, 941110 script etiketi, 941160 HTML enjeksiyonu).

#### Content-Security-Policy raporlaması (XSS için en değerli kaynak)

CSP, tarayıcıya "bu sayfada yalnızca şu kaynaklardan betik çalışabilir" der. İhlal olduğunda tarayıcı bir **JSON rapor** gönderir. Bu, sunucu log'unda görünmeyen DOM XSS'i ve sanitizer atlatmalarını bile gösterir.

```http
Content-Security-Policy: default-src 'self'; script-src 'nonce-{RASTGELE}' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'; report-to csp; report-uri /csp-report
Reporting-Endpoints: csp="https://portal.lab.local/csp-report"
```

- **Önce `Content-Security-Policy-Report-Only`** ile yayına al: hiçbir şeyi engellemez, sadece raporlar. FP'leri (eklentiler, üçüncü taraf betikler) ayıkla, sonra zorunlu moda geç.
- Rapor endpoint'i gelen JSON'u satır satır bir dosyaya yazsın (ör. `/var/log/csp/csp-report.log`) → Wazuh/Splunk.
- **Kritik ayrım:** `disposition: "enforce"` → betik **engellendi** (deneme). `disposition: "report"` → betik **çalıştı** (report-only modda). Yönetici sayfasında report-only ihlali = olası başarı.
- Tarayıcı eklentileri çok gürültü üretir (`blocked-uri` değeri `chrome-extension`, `moz-extension` vb.) → filtrele.

#### Uygulama oturum log'u

Oturum çalmayı yakalamak için uygulama her kimlik doğrulamalı istekte (veya en azından oturum başlangıcında ve hassas işlemlerde) şunları yazmalı: `session_id` (hash'lenmiş), `user`, `src_ip`, `user_agent`, `action`. Aynı oturumun iki farklı IP/UA'dan kullanılması en net sinyaldir. Ayrıca çerezlerin `HttpOnly`, `Secure`, `SameSite` ayarları denetlenmeli (bkz. §4).

#### Microsoft 365 / Exchange / webmail audit

| Kaynak | Olay / alan | Neden |
|---|---|---|
| M365 Unified Audit Log | `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` (parametrelerde `ForwardTo`, `RedirectTo`, `ForwardAsAttachmentTo`, `DeleteMessage`) | Webmail XSS sonrası en yaygın kalıcılık (T1114.003) |
| M365 Unified Audit Log | `Set-Mailbox` (`ForwardingSmtpAddress`), `MailItemsAccessed` (E5/Audit Premium) | Posta kutusu yönlendirme, toplu posta okuma |
| Entra ID sign-in log | Yeni ülke/ASN, token yeniden kullanımı, risk tespitleri | Çalınan oturumun kullanımı |
| Exchange on-prem | IIS log'ları (`/owa/` yolları), *MSExchange Management* olay log'u (cmdlet çağrıları) | OWA XSS'te yönetim işlemleri ve kural oluşturma |
| Roundcube / Zimbra | Kullanıcı log'u, Sieve/filtre kuralı değişikliği, uygulama parolası oluşturma | RoundPress ve CVE-2025-27915 tipi kalıcılık |

Exchange on-prem için EEMS durumunu düzenli kontrol et: Microsoft'un **Exchange Health Checker** betiği raporunda EEMS ve uygulanan önlemleri gösterir.

#### Uç nokta ve ağ

- **Proxy/DNS:** Kullanıcı tarayıcılarının yeni görülen alan adlarına yaptığı istekler; özellikle yönetici/destek ekiplerinin tarayıcılarından herkese açık OAST/geri arama servislerine giden trafik.
- **EDR / Sysmon:** XSS tek başına süreç oluşturmaz; ama drive-by zincirinde (T1189) tarayıcının alt süreç açması (Sysmon EID 1, parent `chrome.exe`/`msedge.exe` → `powershell.exe`, `cmd.exe`, `mshta.exe`) ve tarayıcının indirme klasörüne betik yazması (EID 11) takip edilmeli.

### 3.3 Log analizi: örnek bir saldırının izini okumak

[`ornek.log`](ornek.log) lab'da üretilmiş bir zinciri içerir. Okuma sırası (kim → ne ile → nasıl → sonuç):

1. **Kim?** `203.0.113.60` önce bir XSS aracı UA'sıyla `/search` parametresini yoklar (özel karakter yansıtma testi), sonra tarayıcı UA'sına geçer → otomasyon + gizlenme.
2. **Ne ile?** Reflected denemelerden biri 200 alır (yansıma olası), kodlanmış bir deneme 403 ile engellenir.
3. **Nasıl gelişti?** Aynı IP `/support/ticket` endpoint'ine bir `POST` gönderir; erişim log'unda yalnızca `201` görünür, **gövdeyi ModSecurity Warning satırı gösterir** (CRS 941100, engellenmedi).
4. **Sonuç?** Dakikalar sonra yönetici `198.51.100.25` o ticket'ı açar → aynı sayfa için **CSP raporları** gelir: biri `enforce` (engellendi), diğeri report-only modda (çalıştı). Ardından destek ekibinden bir kullanıcının M365 hesabında, saldırganın IP'sinden **"Correo" adlı dış adrese yönlendirme kuralı** oluşturulur → **hesap ele geçirilmiş, kritik**.

**`ornek.log` satırlarında beklenen kurallar:**

| Dosya bölümü | İçerik | Beklenen Wazuh kuralı |
|---|---|---|
| access satır 2 | XSS aracı UA, karakter yansıtma testi | 100201 |
| access satır 3 | Olay işleyicili etiket, 200 | 100200 → **100202** |
| access satır 4 | HTML entity kodlu betik etiketi, 403 | 100200 |
| access satır 5 | Ticket'a `POST`, 201 (gövde görünmez) | — (WAF satırı ile yakalanır) |
| access satır 6 | `javascript:` URI denemesi, 403, tarayıcı UA | 100200 |
| access satır 7 | Yöneticinin ticket'ı görüntülemesi | — (Splunk `05` korelasyonu) |
| modsec satır 1 | CRS 941100 **Warning** (engellenmedi), `/support/ticket` | 100210 → **100211** |
| modsec satır 2 | CRS 941110 Access denied 403 | 100210 |
| csp satır 1 | `script-src-elem` ihlali, `enforce` | 100220 |
| csp satır 2 | Aynı ihlal, `report` (betik çalıştı) | 100220 → **100221** |
| m365 satır 1 | `New-InboxRule`, `ForwardTo` dış adres | **100230** |

### 3.4 Splunk

Tüm sorgular [`splunk.spl`](splunk.spl) dosyasında.

| # | Katman | Ne yakalar | Önerilen kullanım |
|---|---|---|---|
| 01 | L1 | Çift decode + entity normalizasyonu sonrası XSS yapı kategorileri | Avcılık, saatlik alert |
| 02 | L1 | XSS/web tarayıcı UA'ları ve yüksek varyant hacmi | 15 dk alert, otomatik engelleme tetikleyicisi |
| 03 | L2 | Tek IP'nin çok sayıda parametreye özel karakter denemesi (yansıma testi) | 15 dk alert |
| 04 | L1/L2 | CRS 941xxx: engellenen vs geçen, endpoint ve yöntem ayrımı | Dashboard + alert |
| 05 | L2/L3 | **Stored XSS korelasyonu:** WAF'ın engellemediği XSS'li `POST` + aynı sayfayı sonradan görüntüleyen kullanıcılar | **Yüksek öncelikli** alert |
| 06 | L3 | CSP ihlal raporları: yeni dış kaynaklar, `report` vs `enforce`, eklenti gürültüsü filtreli | 15 dk alert + dashboard |
| 07 | L3 | Blind XSS: kullanıcı/yönetici tarayıcılarından OAST/geri arama alanlarına trafik | Kritik alert |
| 08 | L4 | Oturum çalma: aynı oturum kimliği kısa sürede farklı IP/UA'dan | Yüksek öncelikli alert |
| 09 | L4 | M365: dışa yönlendiren / silen gelen kutusu kuralları, posta kutusu yönlendirme | **Kritik** alert |
| 10 | L4 | Webmail/OWA: tek oturumda olağan dışı hızda posta okuma ve ayar değişikliği | Yüksek öncelikli alert |
| 11 | Hepsi | RBA: kullanıcı ve IP üzerine katman puanları | Ana notable |
| 12 | — | Dashboard panelleri | SOC dashboard |

#### Sorgu yazarken uyulan prensipler

- **Normalize et, sonra eşleştir.** İki kez `urldecode()`, `lower()`, HTML entity kalıplarını (`&#x3c;`, `&#60;`, `&lt;`) `<` ile değiştir; `/` ve boşluk ayraçlarını tek boşluğa indir.
- **Yapıya bak.** `alert` kelimesi değil, "`<` + etiket adı", "`on` + harfler + `=`", "`javascript:` şeması" gibi yapılar. Test dizgileri değişir, yapı değişmez.
- **Risk nesnesini doğru seç.** Reflected/probe için `risk_object=src` (IP); stored/webmail/oturum için `risk_object=user` — asıl kurban kullanıcıdır.
- **İstemci tarafını SIEM'e getir.** CSP raporu ve proxy log'u olmadan stored/DOM XSS büyük ölçüde görünmezdir.

#### Risk tabanlı alarm (RBA) mantığı

| Olay | Risk nesnesi | Puan |
|---|---|---|
| İmza eşleşmesi (403 ile engellenmiş) | src | +5 |
| İmza eşleşmesi, 200 | src | +15 |
| XSS aracı UA / yüksek varyant | src | +25 |
| WAF XSS tetiklendi ama engellenmedi, içerik kaydeden endpoint | src | +50 |
| CSP ihlali `enforce` (yönetici sayfası) | user | +30 |
| CSP ihlali `report` — betik çalıştı | user | +60 |
| Tarayıcıdan OAST/geri arama alanına trafik | user | +80 |
| Oturumun farklı IP/UA'dan yeniden kullanımı | user | +80 |
| Dışa yönlendiren posta kuralı / posta kutusu yönlendirme | user | +100 |

**Eşik:** 24 saatte kullanıcı başına ≥ 100 → *Notable: Olası XSS ile hesap ele geçirme*; IP başına ≥ 60 → *Olası XSS taraması/teslimatı*.

### 3.5 Wazuh

Tüm kurallar ve ayarlar [`wazuh.xml`](wazuh.xml) dosyasında.

#### Yerleşik kurallar

`0245-web_rules.xml` içinde **31105** (XSS girişimi) ve **31106** (web saldırısı 200 ile döndü) bulunur. Microsoft 365 olayları için Wazuh'un `office365` modülü ve yerleşik `office365` kural grubu kullanılır. Sürümünü doğrula:

```bash
grep -n -A6 'id="31105"\|id="31106"' /var/ossec/ruleset/rules/0245-web_rules.xml
grep -ln 'office365' /var/ossec/ruleset/rules/*.xml
```

#### Özel kural seti (100200–100299)

| ID | Seviye | Mantık | Aktif yanıt |
|---|---|---|---|
| 100201 | 10 | XSS aracı User-Agent'ı (imzadan önce değerlendirilir) | firewall-drop 30 dk |
| 100200 | 8 | Gelişmiş XSS imzası (URL ve entity kodlu hâller dahil) | — |
| 100202 | 10 | İmza eşleşen istek 200 döndü (reflected olası — doğrula) | — |
| 100203 | 12 | 2 dk'da aynı IP'den 15+ XSS imzası | firewall-drop 30 dk |
| 100210 | 9 | ModSecurity CRS 941xxx tetiklendi | — |
| 100211 | 12 | CRS XSS kuralı tetiklendi ama istek **engellenmedi** | — |
| 100220 | 10 | CSP `script-src` ihlali (yabancı betik çalışmaya çalıştı) | — |
| 100221 | 12 | CSP ihlali report-only modda — betik **çalıştı** | — |
| 100230 | 12 | M365: dış adrese yönlendiren / silen gelen kutusu kuralı | Yok — analiste / SOAR'a |

**Neden 100211, 100221, 100230'a otomatik engelleme yok?** Bu alarmlarda saldırgan zaten içerik yerleştirmiş veya hesaba ulaşmıştır; IP engellemek kaydedilmiş betiği ya da yönlendirme kuralını kaldırmaz, saldırgan başka IP'den devam eder. Gerekli aksiyon içerik/kural temizliği ve oturum iptalidir → insana veya onaylı SOAR adımına.

#### Test etme

```bash
/var/ossec/bin/wazuh-logtest
# ornek.log içinden "#" ile başlamayan bir satır yapıştır.
# CSP ve M365 satırları JSON'dur; tek satır olarak yapıştır.
```

> M365 satırı gerçek ortamda `office365` modülünden gelir; logtest'te `integration: office365` alanı sayesinde yerleşik office365 kuralına, oradan 100230'a düşmesi beklenir. Yerleşik kural grubunun adı sürümüne göre değişebilir — yukarıdaki `grep` ile doğrula.

### 3.6 Ağ tarafı: PCAP ve Zeek ile doğrulama

**Wireshark görüntüleme filtreleri:**

```
http.request.uri contains "%3cscript" || http.request.uri contains "javascript:"
http.request.method == "POST" && http.request.uri contains "/support/ticket"
http.request and http.referer contains "/admin/"         # yönetici sayfasından çıkan istekler
http.request.uri contains "/csp-report"
dns.qry.name contains "oast" || dns.qry.name contains "interact"
```

*Follow → HTTP Stream* ile stored XSS `POST` gövdesini ve yönetici sayfasının yanıtını incele: kaydedilen içerik yanıtta kodlanmadan mı dönüyor?

**Zeek:** `http.log` içinde `referrer` alanı yönetici paneli olan ve `host` değeri kurum dışı olan istekler blind/stored XSS geri aramasını gösterir. `dns.log`'da yönetici iş istasyonlarından yeni ve düşük itibarlı alan adlarına sorgular aranır.

### 3.7 Yanlış pozitif yönetimi

| FP kaynağı | Belirti | Çözüm |
|---|---|---|
| İç zafiyet tarayıcıları, DAST (ZAP, Burp, Acunetix) | Planlı zamanlarda yüksek hacim | Tarayıcı IP allowlist'i + tarama takvimi |
| Zengin metin editörleri, CMS | Meşru HTML içeren `POST`'lar (CRS 941 tetiklenir) | Endpoint bazlı istisna, sadece yetkili oturumlar; sanitizer'ın sunucu tarafında çalıştığını doğrula |
| Kod paylaşan alanlar (wiki, ticket'a log/kod yapıştırma) | `<script>` metni olarak gönderilen içerik | Yapı + sonuç korelasyonu; tek başına imza alarm üretmesin, RBA puanı yazsın |
| Tarayıcı eklentileri | CSP raporunda `chrome-extension`, `moz-extension`, `safari-web-extension` | Rapor alımında filtrele |
| Üçüncü taraf betikler (analitik, sohbet widget'ı) | Yeni bir dış alan için toplu CSP ihlali | Değişiklik yönetimi; CSP'ye bilinçli ekleme |
| Meşru posta kuralları | Kullanıcının kendi dış adresine yönlendirme | Kurumsal politika: dış yönlendirme genel olarak kapalı; istisnalar listede |

**Kural sağlığı:** Her kural için aylık tetiklenme, TP oranı, ortalama triyaj süresi. L1 imza kuralları TP oranı düşükse alarm değil **puan** üretmeli.

---

## 04 — Önleme, sertleştirme ve olay müdahalesi

### 4.1 Asıl çözüm: bağlama uygun çıktı kodlama ve güvenli DOM API'leri

Girdi doğrulama yardımcıdır; XSS'i kapatan şey **çıktı anında, doğru bağlam için** yapılan kodlamadır.

```php
// PHP – HTML gövdesi ve attribute (ENT_QUOTES + UTF-8 şart)
echo htmlspecialchars($ad, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
// Twig/Blade varsayılan olarak kodlar: {{ ad }} güvenli, {!! ad !!} / |raw TEHLİKELİ
```

```javascript
// Tarayıcı – güvenli sink'ler
el.textContent = kullaniciVerisi;                 // innerHTML yerine
link.href = new URL(girdi, location.origin).protocol.match(/^https?:$/) ? girdi : '#';
// HTML göstermek zorunluysa: sanitizer
el.innerHTML = DOMPurify.sanitize(zenginMetin);   // sanitizasyondan sonra içeriği DEĞİŞTİRME
```

```jsx
// React – JSX {} içi otomatik kodlanır
<p>{yorum}</p>                                     // güvenli
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />   // sadece sanitizer ile
```

```python
# Python – Jinja2 / Django otomatik kaçış açık kalmalı
env = Environment(autoescape=select_autoescape(["html", "xml"]))
# Django: {{ veri }} güvenli; |safe, mark_safe() yalnızca sanitize edilmiş içerik için
```

```csharp
// ASP.NET Core – Razor @veri otomatik kodlar; Html.Raw() TEHLİKELİ
// JS bağlamına veri taşırken:
var json = System.Text.Json.JsonSerializer.Serialize(model);   // <script> içinde değil, data- attribute'unda taşı
```

#### Framework kaçış kapıları

| Framework | Tehlikeli kullanım | Güvenli karşılığı |
|---|---|---|
| React | `dangerouslySetInnerHTML`, `href={girdi}` (`javascript:`) | JSX kodlaması, DOMPurify, URL allowlist |
| Angular | `bypassSecurityTrustHtml/Url/Script` | Yerleşik sanitizer, `DomSanitizer` ile kontrollü kullanım |
| Vue | `v-html` | Metin interpolasyonu `{{ }}`, sanitizer |
| Lit | `unsafeHTML` | Varsayılan şablon bağlama |
| Sunucu şablonları | `raw` / `safe` filtreleri, `{!! !!}`, `Html.Raw` | Varsayılan otomatik kaçış |
| jQuery | `.html(girdi)`, `$(girdi)` | `.text()` |

### 4.2 Katmanlı savunma kontrol listesi

| Katman | Kontrol | Etkisi |
|---|---|---|
| Kod | Bağlama uygun kodlama, güvenli sink'ler, şablon otomatik kaçışı açık | Kök nedeni kapatır |
| Zengin içerik | Güncel DOMPurify (veya eşdeğeri) sunucu ve istemci tarafında | Kullanıcı HTML'ini güvenli hale getirir |
| Kod incelemesi | SAST: CodeQL (`js/xss`, `js/xss-through-dom`), Semgrep, SonarQube; kaçış kapılarını PR'da işaretle | Hatalı kalıbı merge öncesi yakalar |
| Tarayıcı politikası | **Nonce/hash tabanlı katı CSP** (`strict-dynamic`, `object-src 'none'`, `base-uri 'none'`), raporlama açık | Betik çalışmasını engeller **ve** görünürlük sağlar |
| DOM sertleştirme | Trusted Types (`require-trusted-types-for 'script'`) | DOM XSS sink'lerini zorunlu politikaya bağlar |
| Çerez | `HttpOnly`, `Secure`, `SameSite=Lax/Strict`; `__Host-` öneki | Çerez çalmayı zorlaştırır (oturum sürmeyi engellemez!) |
| Hassas işlemler | Parola/e-posta/MFA değişikliğinde yeniden kimlik doğrulama, CSRF token | Betiğin kurban adına kritik işlem yapmasını zorlaştırır |
| Dosyalar | Kullanıcı yüklemelerini ayrı alan adından, `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` | SVG/HTML yükleme ile stored XSS'i keser |
| Webmail | Hızlı yama + KEV takibi, Exchange'te **EEMS açık**, OWA'yı mümkünse internete kapat/VPN veya ön kimlik doğrulama arkasına al | 2024–2026 olaylarının çoğunu önlerdi |
| Posta | Dış adrese otomatik yönlendirmeyi kurum genelinde kapat (Exchange Online giden spam politikası) | XSS sonrası en yaygın kalıcılık yolunu keser |
| WAF | CRS 941xxx, PL2+, DetectionOnly ile başlayıp ayarlama | Otomatik taramaları azaltır (DOM XSS'i görmez) |
| Test | DAST, pentest, bug bounty; blind XSS için iç panellerin test kapsamında olması | Kaçanı bulur |

### 4.3 Olay müdahale playbook'u (NIST SP 800-61 r2)

#### Triyaj karar ağacı

```
Alarm geldi
 ├─ Kaynak iç tarayıcı / onaylı pentest mi? ── Evet → kapat (FP), allowlist'i doğrula
 └─ Hayır
     ├─ Sadece reflected probe'lar, hepsi 403 veya içerik kaydetmeyen GET'ler mi?
     │      └─ Evet → DENEME (P3): IP engelle, parametrenin yanıtta kodlandığını doğrula, kapat
     └─ Hayır
         ├─ İçerik kaydeden endpoint'e engellenmemiş XSS'li POST / webmail'e şüpheli HTML e-posta var mı?
         │      └─ Evet → OLASI STORED (P2): içeriği bul, karantinaya al, görüntüleyenleri listele
         └─ CSP report ihlali / OAST geri araması / oturum yeniden kullanımı / posta kuralı / hesap değişikliği?
                └─ Evet → OLASI BAŞARI (P1) → L2 + IR, aşağıdaki adımlar
```

#### P1 adımları

| # | Aşama | Aksiyon | Sorumlu | Hedef süre |
|---|---|---|---|---|
| 1 | Tespit & analiz | Zararlı içeriği (kayıt ID, e-posta Message-ID) bul; o içeriği görüntüleyen **tüm kullanıcıları** çıkar (erişim log'u + CSP raporları); saldırgan IP/alan adlarını birleştir | L1 → L2 | 30 dk |
| 2 | Delil koruma | Zararlı içeriğin ham hâlini, WAF/CSP/proxy/M365 audit kayıtlarını değiştirilemez depoya al | L2 / DFIR | 1 sa |
| 3 | Kontrol altına alma | İçeriği sil/karantinaya al (webmail'de e-postayı tüm posta kutularından kaldır); etkilenen kullanıcıların **tüm oturumlarını ve token'larını iptal et**; saldırgan alanlarını proxy/DNS'te engelle; endpoint'e virtual patch | L2 + uygulama + mesajlaşma ekibi | 1 sa |
| 4 | Kalıcılık temizliği | Posta yönlendirme/silme kuralları, posta kutusu yönlendirme, uygulama parolaları, yeni MFA yöntemleri, yeni admin hesapları, OAuth onayları | IAM + mesajlaşma | 4 sa |
| 5 | Etki analizi | Hangi postalar/kayıtlar okundu (`MailItemsAccessed`, uygulama log'u), hangi işlemler kurban adına yapıldı, kişisel veri var mı? | DFIR | 24 sa |
| 6 | Temizleme | Kodu düzelt veya ürün yamasını uygula (KEV ise acil); aynı kalıbı tüm kod tabanında SAST ile ara; CSP'yi zorunlu moda al | Uygulama + sistem | 48 sa |
| 7 | Kimlik bilgisi rotasyonu | Etkilenen kullanıcı parolaları, oturum imzalama anahtarları (gerekirse), API anahtarları | IAM | 48 sa |
| 8 | Kurtarma | 30 gün yükseltilmiş izleme: aynı alanlar, aynı göndericiler, aynı kural adları | SOC | — |
| 9 | Yasal bildirim | Kişisel veri sızdıysa KVKK m.12 uyarınca Kurul'a **72 saat** içinde bildirim, ilgili kişilere bildirim; sektörel düzenlemeler (BDDK vb.) | Hukuk + CISO | 72 sa |
| 10 | Öğrenilen dersler | Kök neden; kaçırılan sinyali kurala ekle; CSP raporlamasını yaygınlaştır; geliştirici eğitimi | Tüm ekipler | 2 hafta |

#### Analist ticket şablonu

```
Başlık     : [P1] Olası stored XSS ile hesap ele geçirme - <uygulama> - <etkilenen kullanıcı(lar)>
Tetikleyen : Wazuh 100211/100221/100230 · Splunk RBA user=<kullanıcı> risk=<puan>
Zaman      : Teslimat <ts> · İlk çalışma (CSP/geri arama) <ts> · İlk kötüye kullanım <ts>
Kaynak     : <IP listesi>, ASN, itibar; C2/geri arama alanları
Taşıyıcı   : <endpoint + kayıt ID> veya <e-posta Message-ID, gönderici>
Kurbanlar  : <içeriği görüntüleyen kullanıcılar, yetki seviyeleri>
Gözlem     : <CSP disposition, dış istekler, oturum yeniden kullanımı, posta kuralı adı/hedefi>
Etki       : <okunan postalar/kayıtlar, yapılan işlemler, kişisel veri: evet/hayır>
Aksiyonlar : <içerik karantinası, oturum iptali, kural silme, parola/MFA sıfırlama, engelleme>
Sonraki    : <yama, kod düzeltmesi, CSP zorunlu mod, sorumlular>
```

### 4.4 SOAR otomasyonu (Shuffle)

1. **Tetik:** Wazuh integration (`<integration><name>shuffle</name><hook_url>...</hook_url><rule_id>100201,100203,100211,100221,100230</rule_id></integration>`).
2. **Zenginleştirme:** Kaynak IP ve CSP'deki `blocked-uri` alanı için VirusTotal/AbuseIPDB/URLhaus; Splunk'tan kullanıcının 24 saatlik RBA puanı; M365 Graph API ile kullanıcının mevcut gelen kutusu kuralları ve son oturum açmaları.
3. **Dallanma:**
    - 100201/100203 → WAF/firewall API ile IP engelle, P3 vaka, otomatik kapat.
    - 100211/100221 → P2 vaka; ilgili sayfayı görüntüleyen kullanıcı listesini Splunk'tan çek ve vakaya ekle; uygulama ekibine bildirim.
    - 100230 → P1 vaka; Teams/Slack'e L2 bildirimi; **onay butonu** ile: kuralı devre dışı bırak, kullanıcı oturumlarını iptal et (Graph `revokeSignInSessions`), parola sıfırlamayı başlat.
4. **Kapanış:** Vakaya tüm zenginleştirme, ham log bağlantıları ve yapılan aksiyonlar eklenir.

---

## 05 — Pratik: odalar, lab ve kaynaklar

### 5.1 Önerilen sıra

| # | Platform | Oda / ders | Odak |
|---|---|---|---|
| 1 | TryHackMe | [XSS](https://tryhackme.com/room/axss) | Türler, kök neden, Same-Origin Policy, dillere göre önleme |
| 2 | TryHackMe | [Intro to Cross-site Scripting](https://tryhackme.com/room/xss) (Premium) | Reflected/stored/DOM/blind ve uygulamalı blind XSS lab'ı |
| 3 | PortSwigger | [Web Security Academy – Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting) | Ücretsiz, bağlama göre ayrılmış lab'lar; CSP ve DOM XSS |
| 4 | PortSwigger | [Content security policy](https://portswigger.net/web-security/cross-site-scripting/content-security-policy) | CSP'nin XSS'i nasıl sınırladığı |
| 5 | TryHackMe | [OWASP Juice Shop](https://tryhackme.com/room/owaspjuiceshop) | Gerçekçi uygulamada XSS |
| 6 | LetsDefend | [Detecting Web Attacks](https://app.letsdefend.io/training/lessons/web-attacks-101) | Web log'undan XSS tespiti |
| 7 | LetsDefend | [Detecting XSS Attacks in SOC Environment](https://letsdefend.io/blog/detecting-xss-cross-site-scripting-attacks-in-soc-environment) | Analist bakışıyla özet |
| 8 | LetsDefend | Monitoring kuyruğundaki web saldırısı (XSS) alarmları | Gerçek ticket akışı: triyaj, log yönetimi, kapatma |

### 5.2 Kendi detection lab'ın

```
[Kali / saldırgan VM] ──HTTP──> [Ubuntu: Nginx/Apache + ModSecurity + DVWA/Juice Shop]
                                      │  /csp-report endpoint → /var/log/csp/csp-report.log
                                      │  Wazuh agent (access/error/csp log + FIM)
                                      ▼
[Windows "yönetici" VM: Edge + Sysmon] ──proxy log──> [Wazuh manager] [Splunk Free/Dev]
```

1. DVWA veya Juice Shop'u kur; #001 §3.2'deki log formatlarını uygula.
2. Uygulamanın önüne bir CSP header'ı ekle: önce `Report-Only`, `report-uri /csp-report`. Rapor endpoint'i için küçük bir betik gelen JSON'u satır satır dosyaya yazsın.
3. [`wazuh.xml`](wazuh.xml) Bölüm C'yi agent'a, A ve B'yi manager'a uygula.
4. DVWA XSS (reflected/stored/DOM) modüllerini "low" seviyede çalıştır. Her türde hangi katmanın (erişim log'u / WAF / CSP raporu) sinyal ürettiğini bir tabloya not et — **DOM türünde sunucu log'unda hiçbir şey göremediğini** gözlemle.
5. "Yönetici" VM'den stored içeriği aç; proxy log'unda ve CSP raporunda ne oluştuğunu incele. Sonra CSP'yi zorunlu moda al ve farkı gör.
6. Kuralları [`ornek.log`](ornek.log) ile `wazuh-logtest` üzerinden doğrula.

### 5.3 Kendini test et

1. DOM-based XSS'i sunucu erişim log'unda neden çoğu zaman göremezsin? Hangi iki kaynak bu boşluğu kapatır?
2. CSP raporunda `disposition` alanı neden kritik? `report` değeri ne anlama gelir?
3. `HttpOnly` çerez, XSS saldırganının kurban adına işlem yapmasını neden engellemez?
4. RoundPress gibi bir webmail XSS kampanyasında, betik kalıcı olmadığı hâlde saldırganın erişimi nasıl sürer ve SOC bunu nerede yakalar?
5. Neden 100230 kuralına otomatik IP engelleme bağlamadık; bunun yerine hangi aksiyonlar gerekir?

<details><summary>Cevaplar</summary>

1. URL'nin `#` sonrası (fragment) ve `postMessage` verisi sunucuya gönderilmez; zararlı veri istemcide işlenir. Boşluğu **CSP ihlal raporları** ve **proxy/DNS (tarayıcıdan dış istekler)** kapatır; EDR tarayıcı telemetrisi de yardımcı olur.
2. `enforce` betiğin engellendiğini (deneme), `report` ise politika report-only modda olduğu için betiğin **çalıştığını** gösterir. İkincisi olası başarıdır.
3. Betik zaten kurbanın oturumunda, aynı kökende çalışır; çerezi okumadan aynı kökene kimlik doğrulamalı istek atabilir (oturum sürme, T1185). HttpOnly yalnızca çerezin dışarı taşınmasını zorlaştırır.
4. Hesap tarafında kalıcılık kurulur: posta yönlendirme/filtre kuralı, uygulama parolası, MFA atlatma. SOC bunu M365/webmail audit log'larında (kural ve hesap değişikliği) ve yeni IP'den oturum kullanımında yakalar.
5. Saldırgan zaten hesaba ulaşmıştır; IP engellemek kuralı silmez, saldırgan başka IP'den devam eder ve yanlış engelleme meşru kullanıcıyı keser. Gerekenler: kuralı kaldırmak, oturumları iptal etmek, parola/MFA sıfırlamak, etki analizi — insan onaylı.

</details>

### 5.4 Kaynaklar

- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MITRE CWE-79](https://cwe.mitre.org/data/definitions/79.html) · [ATT&CK T1189 Drive-by Compromise](https://attack.mitre.org/techniques/T1189/) · [T1539](https://attack.mitre.org/techniques/T1539/) · [T1185](https://attack.mitre.org/techniques/T1185/) · [T1114.003](https://attack.mitre.org/techniques/T1114/003/)
- [OWASP Core Rule Set](https://coreruleset.org/) (941xxx XSS kuralları)
- [MDN – Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) · [DOMPurify](https://github.com/cure53/DOMPurify)
- [ESET – Operation RoundPress](https://www.welivesecurity.com/de/eset-research/operation-roundpress) · [BleepingComputer – RoundPress](https://www.bleepingcomputer.com/news/security/government-webmail-hacked-via-xss-bugs-in-global-spy-campaign/)
- [CVE-2026-42897 (Exchange OWA) – CyCognito](https://www.cycognito.com/blog/emerging-threat-cve-2026-42897-microsoft-exchange-owa-cross-site-scripting-via-crafted-email/) · [BleepingComputer – yama](https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-exchange-server-zero-day-exploited-in-attacks/amp/)
- [CVE-2025-27915 (Zimbra) – The Hacker News](https://thehackernews.com/2025/10/zimbra-zero-day-exploited-to-target.html) · [CVE-2025-68461 (Roundcube) – Cyber Security News](https://cybersecuritynews.com/roundcube-vulnerabilities-exploited/) · [CVE-2024-11182 (MDaemon)](https://cybersecuritynews.com/cisa-adds-mdaemon-email-server-xss-vulnerability/)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Splunk Security Content (ESCU)](https://research.splunk.com/) — "XSS", "Inbox Rule" aramaları
