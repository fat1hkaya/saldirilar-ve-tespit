# Saldırılar ve Tespit

> 500+ siber saldırının **nasıl çalıştığı, saldırı akışında hangi izleri bıraktığı, nasıl tespit edildiği ve nasıl önlendiği** — SOC analisti bakış açısıyla, Türkçe, profesyonel seviyede.

Her saldırı aynı şablonla, baştan sona işlenir: kök neden → saldırı akışı ve her aşamanın izi → log kaynakları ve gösterge analizi → **Splunk SPL** sorguları → **Wazuh** decoder/kural/aktif yanıt → önleme → olay müdahale playbook'u → TryHackMe ve LetsDefend pratiği.

Hazırlayan: **Fatih Kaya** — Bilgisayar Mühendisliği, Marmara Üniversitesi · [LinkedIn](https://linkedin.com/in/fatihsec) · [GitHub](https://github.com/fat1hkaya)

---

## ⚠️ Yasal uyarı

Bu repo **savunma (blue team) eğitimi** amaçlıdır. Saldırı akışı bölümleri, tespit kurallarının *neden* öyle yazıldığını anlamak için vardır. Tüm teknikler yalnızca **sahibi olduğun veya yazılı izin aldığın** sistemlerde ve kasıtlı zafiyetli lab ortamlarında (DVWA, Juice Shop, TryHackMe, HackTheBox, PortSwigger Academy) denenmelidir. İzinsiz erişim Türkiye'de **TCK 243–245** maddeleri kapsamında suçtur.

---

## İlerleme

| # | Saldırı | Kategori | Seviye | Tarih | Klasör |
|---|---|---|---|---|---|
| 001 | SQL Injection (SQLi) | Web | Temel → İleri | 2026-10-24 | [01-web/001-sql-injection](01-web/001-sql-injection/) |

Tüm plan: [ROADMAP.md](ROADMAP.md)

## Kategoriler

| Klasör | Kategori | Planlanan |
|---|---|---|
| `01-web` | Web uygulama saldırıları | ~80 |
| `02-ag-ddos` | Ağ saldırıları ve DDoS | ~60 |
| `03-active-directory` | Active Directory ve kimlik | ~60 |
| `04-windows-linux` | Uç nokta: Windows / Linux (PrivEsc, persistence, LOLBins) | ~70 |
| `05-bulut` | Bulut (AWS / Azure / GCP / Kubernetes / container) | ~50 |
| `06-malware` | Malware, ransomware, C2 | ~50 |
| `07-sosyal-muhendislik` | Phishing, BEC, MFA saldırıları | ~40 |
| `08-mobil-iot-ot` | Mobil, IoT, OT/ICS | ~40 |
| `09-tedarik-zinciri-ai` | Tedarik zinciri, CI/CD, AI/LLM saldırıları | ~50 |

## Her saldırı klasörünün yapısı

Her saldırı 4 dosyadır: tek bir dokümanda baştan sona okunur, kurallar ayrı dosyalarda kopyalanmaya hazırdır.

```
NNN-saldiri-adi/
├── README.md    # Tüm anlatım: özet kartı → teori → saldırı akışı → tespit → önleme/IR → pratik
├── splunk.spl   # Tüm SPL sorguları, numaralı bölümler
├── wazuh.xml    # Bölüm A: local_rules · Bölüm B: aktif yanıt · Bölüm C: agent ayarları
└── ornek.log    # Kuralları test etmek için örnek log satırları
```

## Kuralları kullanma

- **Splunk:** `splunk.spl` içindeki `=====` ayraçları arasındaki her bölüm ayrı bir aramadır; Search & Reporting'e yapıştır, `index`/`sourcetype` değerlerini kendi ortamına göre değiştir. Kalıcı hale getirmek için *Save As → Alert* veya ES'te *Correlation Search*.
- **Wazuh:** `wazuh.xml` Bölüm A'yı manager'da `/var/ossec/etc/rules/local_rules.xml` dosyasına ekle, `/var/ossec/bin/wazuh-logtest` ile `ornek.log` satırlarını test et, sonra `systemctl restart wazuh-manager`.
- **Kural ID düzeni:** Wazuh özel kural ID'leri saldırı numarasına göre bloklanır: `#001 → 100100–100199`, `#002 → 100200–100299`, … çakışma olmaz.

## Lisans

İçerik [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) · Kod parçaları (SPL/XML) MIT.
