# PROXMARK RFID ANALYZER

> **RFID/NFC kart güvenlik analiz aracı** — Proxmark3 çıktılarını okuyarak kart türünü otomatik tespit eder, CVSS tabanlı güvenlik açığı analizi yapar, saldırı matrisini çıkarır ve hem terminal hem Markdown rapor üretir.

---

## Etik Kullanım Bildirimi

Bu araç **yalnızca eğitim, araştırma ve yetkili güvenlik testi** amaçlı geliştirilmiştir.

- Analiz ettiğiniz kartlar **size ait** veya **yazılı izin aldığınız** kartlar olmalıdır.
- Başkalarına ait RFID/NFC kartları **izinsiz** taramak, klonlamak veya manipüle etmek **yasa dışıdır** ve etik değildir.
- Yetkisiz kullanımdan doğacak tüm hukuki sorumluluk **kullanıcıya** aittir.
- Araç, RFID güvenlik açıklarını anlamanız ve savunma önlemleri geliştirmeniz için tasarlanmıştır.

> **Kötüye kullanım durumunda geliştirici hiçbir sorumluluk kabul etmez.**

---

## 🚀 Tek Satırda Kur (Linux / macOS / WSL)

```bash
curl -fsSL https://raw.githubusercontent.com/Cinargenc/proxmark3_rfid_analyzer/main/install.sh | bash
```

Gereksinimler: `git`, `python3` (harici kütüphane gerekmez)

---

## Manuel Kurulum

```bash
git clone https://github.com/Cinargenc/proxmark3_rfid_analyzer.git
cd proxmark3-tool
python3 main.py samples/mifare_classic_1k.txt
```

---

## Kullanım

### Kart Analizi

```
python3 main.py <proxmark3_log_dosyası.txt>
```

#### Örnekler

```bash
# MIFARE ailesi
python3 main.py samples/mifare_classic_1k.txt        # MIFARE Classic 1K
python3 main.py samples/mifare_classic_4k.txt         # MIFARE Classic 4K
python3 main.py samples/mifare_classic_cafeteria.txt  # Yemekhane kartı
python3 main.py samples/mifare_desfire.txt            # DESFire EV1
python3 main.py samples/mifare_plus_sl1.txt           # MIFARE Plus SL1
python3 main.py samples/mifare_ultralight_ntag.txt    # Ultralight / NTAG

# LF Kartlar
python3 main.py samples/hid_proximity.txt             # HID Proximity (125 kHz)
python3 main.py samples/hid_prox_cafeteria.txt        # HID Prox — kafeterya erişim
python3 main.py samples/hid_iclass_turnstile.txt      # HID iCLASS — turnike

# Ulaşım & Ödeme
python3 main.py samples/transit_istanbulkart.txt      # İstanbulkart
python3 main.py samples/calypso_bus_card.txt          # Calypso otobüs kartı
python3 main.py samples/felica_transit.txt            # Sony FeliCa transit
python3 main.py samples/emv_credit_card.txt           # EMV temassız ödeme kartı

# Diğer
python3 main.py samples/iso15693_library.txt          # ISO15693 kütüphane etiketi
python3 main.py samples/st25tb_ticket.txt             # ST25TB bilet
python3 main.py my_card_output.txt                    # Kendi Proxmark3 çıktın
```

### Zafiyet Veritabanı Sorgulama

Kart taramaya gerek kalmadan zafiyet veritabanını doğrudan sorgulayabilirsiniz:

```bash
python3 vuln_query.py                          # Tüm zafiyetleri listele
python3 vuln_query.py --id RFID-002            # Tek zafiyet detayı
python3 vuln_query.py --tag broken-crypto      # Etikete göre filtrele
python3 vuln_query.py --family MIFARE_CLASSIC_1K  # Kart ailesine göre
python3 vuln_query.py --min-cvss 7.0           # CVSS ≥ 7.0 (HIGH + CRITICAL)
python3 vuln_query.py --severity CRITICAL      # Sadece CRITICAL seviye
python3 vuln_query.py --info                   # Veritabanı meta bilgisi
```

---

## Desteklenen Kart Tipleri

### LF — 125 kHz

| Kart | Şifreleme | Risk |
|------|-----------|------|
| EM410x | Yok | 🔴 CRITICAL |
| EM4200 | Yok | 🔴 CRITICAL |
| HID Proximity | Yok | 🔴 CRITICAL |
| AWID | Yok | 🔴 CRITICAL |
| Indala | Yok | 🔴 CRITICAL |
| Paradox | Yok | 🔴 CRITICAL |
| T5577 (Writable) | Yok | 🔴 CRITICAL |

### HF — 13.56 MHz (MIFARE)

| Kart | Şifreleme | Risk |
|------|-----------|------|
| MIFARE Classic Mini/1K/4K | Crypto1 (**kırık**) | 🔴 CRITICAL |
| MIFARE Plus SL1 | Crypto1 (**kırık**) | 🔴 HIGH |
| MIFARE Ultralight | Yok | 🟠 HIGH |
| MIFARE Ultralight C | 3DES | 🟡 MEDIUM |
| NTAG213 / NTAG216 | Yok | 🟠 HIGH |
| NTAG424 DNA | AES-128 + SUN | 🟢 LOW |
| MIFARE Plus SL3 | AES-128 | 🟢 LOW |
| MIFARE DESFire EV1/EV2/EV3 | AES-128 | 🟢 LOW |

### HF — 13.56 MHz (Diğer)

| Kart | Şifreleme | Risk |
|------|-----------|------|
| HID iCLASS (Legacy) | DES (**kırık**) | 🔴 HIGH |
| HID iCLASS SE / Seos | AES-128 | 🟢 LOW |
| LEGIC Prime | Proprietary (**kırık**) | 🔴 HIGH |
| LEGIC Advant | AES | 🟢 LOW |
| Sony FeliCa | DES / AES | 🟡 MEDIUM |
| Sony FeliCa Lite | Yok | 🟠 HIGH |
| Calypso | 3DES / AES | 🟡 MEDIUM |
| ST25TB | Yok | 🟠 HIGH |
| ISO15693 / ICODE SLIX | Yok | 🟠 HIGH |

### EMV

| Kart | Şifreleme | Risk |
|------|-----------|------|
| EMV Contactless (Modern) | RSA / AES (dinamik) | 🟡 MEDIUM |
| EMV Pre-2.x (Eski) | RSA (statik) | 🟠 HIGH |
| ISO14443-B Payment | RSA / AES | 🟡 MEDIUM |

---

## Analiz Aşamaları

```
[Log Dosyası] → Parser → Fingerprint Engine → Kart Profili Eşleştirme
                                                       │
                    ┌──────────────────────────────────┤
                    ▼                                  ▼
             6 Analiz Modülü                   Zafiyet Motoru
          (UID, Protocol, Timing,          (CVSS v3.1, vuln_db.json)
           EMV, LF, MIFARE)                        │
                    │                              ▼
                    ▼                      Zafiyet Raporu (.md)
             Risk Skorlama
             Saldırı Matrisi
                    │
                    ▼
         Terminal Raporu (renkli)
         + JSON Raporu (.json)
```

Her analiz sonucunda:
- **Terminal:** Renkli güvenlik raporu — kart bilgisi, risk skoru, saldırı senaryoları, öneriler
- **JSON:** `reports/report_YYYYMMDD_HHMMSS.json` — makinece okunabilir rapor
- **Markdown:** `reports/vuln_report_YYYYMMDD_HHMMSS.md` — CVSS skorlu detaylı zafiyet raporu

---

## Proje Yapısı

```
proxmark3-tool/
├── main.py                    # Ana giriş noktası — kart analiz pipeline'ı
├── vuln_query.py              # Zafiyet veritabanı CLI sorgu aracı
├── install.sh                 # Tek satır otomatik kurulum scripti
│
├── core/                      # Analiz motoru
│   ├── parser.py              # Proxmark3 log çıktısı ayrıştırıcı
│   ├── fingerprint_engine.py  # SAK/ATQA/ATS bazlı kart parmak izi eşleştirme
│   ├── card_profiles.py       # 30+ kart profili veritabanı
│   ├── scoring.py             # Risk skor hesaplama
│   ├── threat_engine.py       # Saldırı vektörü değerlendirmesi
│   ├── report.py              # Terminal rapor üreteci (renkli + JSON)
│   ├── vuln_engine.py         # CVSS tabanlı zafiyet motoru (trigger sistemi)
│   ├── vuln_report_writer.py  # Markdown zafiyet rapor yazıcı
│   └── analyzers/             # Alt analiz modülleri
│       ├── uid_analysis.py    # UID entropi ve klonlama analizi
│       ├── protocol_analysis.py  # Protokol güvenlik analizi
│       ├── timing_analysis.py # Zamanlama/relay saldırı analizi
│       ├── emv_analysis.py    # EMV temassız ödeme analizi
│       ├── lf_analysis.py     # LF 125 kHz kart analizi
│       └── mifare_analysis.py # MIFARE sektör/anahtar analizi
│
├── data/
│   └── vuln_db.json           # CVSS v3.1 zafiyet tanım veritabanı (10 entry)
│
├── samples/                   # 15 örnek Proxmark3 log dosyası
│   ├── mifare_classic_1k.txt
│   ├── mifare_classic_4k.txt
│   ├── mifare_classic_cafeteria.txt
│   ├── mifare_desfire.txt
│   ├── mifare_plus_sl1.txt
│   ├── mifare_ultralight_ntag.txt
│   ├── hid_proximity.txt
│   ├── hid_prox_cafeteria.txt
│   ├── hid_iclass_turnstile.txt
│   ├── transit_istanbulkart.txt
│   ├── calypso_bus_card.txt
│   ├── felica_transit.txt
│   ├── emv_credit_card.txt
│   ├── iso15693_library.txt
│   └── st25tb_ticket.txt
│
└── reports/                   # Üretilen raporlar (gitignored)
    ├── report_*.json          # Kart analiz raporları
    └── vuln_report_*.md       # Zafiyet raporları
```

---

## Özellikler

- **Otomatik Kart Tanıma** — SAK, ATQA, ATS, LF modülasyon desenlerine göre 30+ kart profilini otomatik eşleştirir
- **CVSS v3.1 Zafiyet Motoru** — JSON tabanlı trigger sistemiyle dinamik zafiyet değerlendirmesi
- **Saldırı Matrisi** — Tespit edilen kart tipine uygun saldırı senaryoları ve araçları
- **Risk Skorlama** — Çoklu faktörlü (kripto, UID, protokol, zamanlama) risk hesaplama
- **Çoklu Rapor Çıktısı** — Renkli terminal, JSON ve Markdown formatında raporlar
- **Zafiyet Veritabanı CLI** — `vuln_query.py` ile filtreleme ve arama
- **Platform Desteği** — Linux, macOS, WSL ve Windows'ta çalışır (ANSI renk desteği dahil)
- **Sıfır Bağımlılık** — Sadece Python 3 standart kütüphanesi

---

## Lisans

MIT
