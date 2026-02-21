# proxmark3-tool

> **RFID/NFC kart güvenlik analiz aracı** — Proxmark3 çıktılarını okuyarak kart türünü tespit eder, güvenlik açıklarını analiz eder ve renkli terminal raporu üretir.

---

## ⚡ Tek Satırda Kur (Linux / macOS / WSL)

```bash
curl -fsSL https://raw.githubusercontent.com/Cinargenc/proxmark3-tool/main/install.sh | bash
```

Gereksinimler: `git`, `python3`

---

## Manuel Kurulum

```bash
git clone https://github.com/Cinargenc/proxmark3-tool.git
cd proxmark3-tool
python3 main.py samples/mifare_classic_1k.txt
```

---

## Kullanım

```
python3 main.py <proxmark3_log_dosyası.txt>
```

### Örnekler

```bash
python3 main.py samples/mifare_classic_1k.txt   # MIFARE Classic 1K
python3 main.py samples/mifare_classic_4k.txt   # MIFARE Classic 4K
python3 main.py samples/mifare_desfire.txt       # DESFire EV1
python3 main.py samples/mifare_plus_sl1.txt      # MIFARE Plus SL1
python3 main.py samples/mifare_ultralight_ntag.txt  # Ultralight / NTAG
python3 main.py samples/hid_proximity.txt        # HID Proximity (LF)
python3 main.py my_card_output.txt               # Kendi Proxmark3 çıktın
```

---

## Desteklenen Kart Tipleri

| Kart | Frekans | Şifreleme | Risk |
|------|---------|-----------|------|
| MIFARE Classic 1K/4K | 13.56 MHz | Crypto1 (**kırık**) | 🔴 CRITICAL |
| MIFARE Plus SL1 | 13.56 MHz | Crypto1 (**kırık**) | 🔴 HIGH |
| MIFARE Ultralight/NTAG | 13.56 MHz | Yok | 🟠 HIGH |
| HID Proximity / EM410x | 125 kHz | Yok | 🔴 CRITICAL |
| EMV Contactless | 13.56 MHz | RSA/AES | 🟡 MEDIUM |
| MIFARE DESFire | 13.56 MHz | AES-128 | 🟢 LOW |
| MIFARE Plus SL3 | 13.56 MHz | AES-128 | 🟢 LOW |

---

## Proje Yapısı

```
proxmark3-tool/
├── main.py              # Giriş noktası
├── install.sh           # Curl ile otomatik kurulum
├── core/                # Analiz motoru
│   ├── parser.py
│   ├── fingerprint_engine.py
│   ├── card_profiles.py
│   ├── scoring.py
│   ├── threat_engine.py
│   ├── report.py
│   └── analyzers/
│       ├── uid_analysis.py
│       ├── protocol_analysis.py
│       ├── timing_analysis.py
│       ├── emv_analysis.py
│       ├── lf_analysis.py
│       └── mifare_analysis.py
├── samples/             # Örnek Proxmark3 log dosyaları
└── reports/             # Üretilen JSON raporlar (gitignored)
```

---

## Rapor Çıktısı

Her analizde:
- **Terminal:** Renkli güvenlik raporu (risk skoru, saldırı matrisi, öneriler)
- **JSON:** `reports/report_YYYYMMDD_HHMMSS.json` (makine okunabilir)

---

## Lisans

MIT
