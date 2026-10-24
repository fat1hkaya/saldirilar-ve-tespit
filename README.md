# Saldırılar ve Tespit

> Kurumsal SOC için **en önemli 100 siber saldırının** nasıl çalıştığı, saldırı akışında hangi izleri bıraktığı, nasıl tespit edildiği ve nasıl önlendiği — SOC analisti bakış açısıyla, Türkçe, profesyonel seviyede.

Her saldırı aynı şablonla, baştan sona işlenir: kök neden → saldırı akışı ve her aşamanın izi → log kaynakları ve gösterge analizi → **Splunk SPL** sorguları → **Wazuh** decoder/kural/aktif yanıt → önleme → olay müdahale playbook'u → TryHackMe ve LetsDefend pratiği.

Hazırlayan: **Fatih Kaya** — Bilgisayar Mühendisliği, Marmara Üniversitesi · [LinkedIn](https://linkedin.com/in/fatihsec) · [GitHub](https://github.com/fat1hkaya)

---

## ⚠️ Yasal uyarı

Bu repo **savunma (blue team) eğitimi** amaçlıdır. Saldırı akışı bölümleri, tespit kurallarının *neden* öyle yazıldığını anlamak için vardır. Tüm teknikler yalnızca **sahibi olduğun veya yazılı izin aldığın** sistemlerde ve kasıtlı zafiyetli lab ortamlarında (DVWA, Juice Shop, TryHackMe, HackTheBox, PortSwigger Academy) denenmelidir. İzinsiz erişim Türkiye'de **TCK 243–245** maddeleri kapsamında suçtur.

---

## İlerleme

| # | Saldırı | Bölüm | Öncelik | Tarih | Klasör |
|---|---|---|---|---|---|
| 001 | SQL Injection (SQLi) | 1. Web ve sınır cihazları | 🔴 Kritik | 2026-10-24 | [01-web/001-sql-injection](01-web/001-sql-injection/) |

Tüm liste ve öncelikler: [ROADMAP.md](ROADMAP.md)

## Kapsam

Liste, kurumsal bir SOC'un gerçekte karşılaştığı ortama göre seçildi: Windows ve Active Directory ağırlıklı iç ağ, Microsoft 365 ve Entra ID, internete açık web uygulamaları ve VPN/firewall gibi sınır cihazları, hibrit bulut. Bölümler bir saldırganın kurum içinde izlediği yolu takip eder; numara aynı zamanda çalışma sırasıdır.

| Bölüm | Klasör | Aralık |
|---|---|---|
| 1. Web uygulamaları ve sınır cihazları | `01-web` | 001–010 |
| 2. Phishing ve sosyal mühendislik | `02-phishing` | 011–020 |
| 3. Kimlik bilgisi saldırıları | `03-kimlik` | 021–030 |
| 4. Active Directory | `04-active-directory` | 031–044 |
| 5. Yürütme ve savunma atlatma | `05-yurutme-atlatma` | 045–055 |
| 6. Kalıcılık ve yetki yükseltme | `06-kalicilik-yetki` | 056–065 |
| 7. Yanal hareket ve C2 | `07-yanal-hareket-c2` | 066–075 |
| 8. Sızdırma, ransomware ve etki | `08-sizdirma-etki` | 076–084 |
| 9. Ağ saldırıları ve DDoS | `09-ag-ddos` | 085–090 |
| 10. Bulut, SaaS, tedarik zinciri ve AI | `10-bulut-tedarik` | 091–100 |

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
- **Kural ID düzeni:** Wazuh özel kural ID'leri saldırı numarasına göre 100'lük bloklardır: `100000 + (numara × 100)`. Örnek: `#001 → 100100–100199`, `#045 → 104500–104599`, `#100 → 110000–110099`. Çakışma olmaz.

## Lisans

İçerik [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/) · Kod parçaları (SPL/XML) MIT.
