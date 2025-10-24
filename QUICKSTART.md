# 🚀 Quick Start Guide

## Schnellstart in 3 Schritten:

### 1. OpenAI API Key eintragen

Öffne die `.env` Datei und trage deinen OpenAI API Key ein:

```env
OPENAI_API_KEY=sk-proj-DEIN-ECHTER-KEY-HIER
```

> API Key bekommst du auf: https://platform.openai.com/api-keys

### 2. Server starten

```bash
npm start
```

Oder mit Auto-Reload für Development:

```bash
npm run dev
```

### 3. Browser öffnen

Öffne: **http://localhost:3000**

---

## 🎮 Spielablauf:

### Schritt 1: Benutzername herausfinden (Social Engineering Challenge!)
- Klicke auf **"Benutzernamen vergessen?"**
- Klicke auf **"Anruf an den Support"**
- **Erlaube Mikrofon-Zugriff** (Browser fragt)
- ⚠️ **WICHTIG:** Der Support gibt den Benutzernamen NICHT direkt preis!
- **Du musst ihn überreden/austricksen:**
  - Erzähle eine emotionale Geschichte (kranke Verwandte, wichtige Dokumente)
  - Baue Zeitdruck auf ("Extrem dringend!")
  - Gib dich als wichtige Person aus (Chef, IT-Admin)
  - Sei hartnäckig und kreativ!
- Nach 2-3 überzeugenden Versuchen sollte der Support nachgeben

**Benutzername:** `Robin12345` (aber du musst ihn dir verdienen! 😉)

### Schritt 2: SQL-Injection Bypass
- **Option A:** Injection im Passwort-Feld
  - Benutzername: `Robin12345`
  - Passwort: Eine SQL-Injection Payload (z.B. `' OR '1'='1`)
  
- **Option B:** Injection direkt im Benutzernamen
  - Benutzername: `Robin12345' OR '1'='1`
  - Passwort: (egal, kann leer bleiben)

- **Beispiel-Payloads:**
  - `' OR '1'='1`
  - `' OR 1=1--`
  - `admin'--`
  - `' OR 'x'='x`
  - `" OR "1"="1`
  - `' UNION SELECT`
  - `' OR true--`
  
- Klicke auf **"Anmelden"**

### Schritt 3: Erfolg! 🎉
Du siehst jetzt das Fake-Dateisystem mit der wichtigen Datei!

---

## 🔧 Troubleshooting

**Problem:** "WebSocket connection failed"
- ✅ Server läuft auf Port 3000? → `npm start`
- ✅ Browser-URL ist `localhost:3000`?

**Problem:** "Keine API-Verbindung" oder "Verbindungsfehler"
- ✅ `.env` Datei existiert?
- ✅ `OPENAI_API_KEY` korrekt eingetragen?
- ✅ Server läuft? → `npm start`
- ✅ Server neu gestartet nach `.env` Änderung?
- ✅ Browser-Console auf Fehler prüfen (F12)

**Problem:** "Mikrofon-Zugriff verweigert"
- ✅ Browser-Berechtigung erlauben
- ✅ Funktioniert nur über `localhost` oder `https://`

---

## 📝 Gültige Login-Credentials

**Option 1 (normale Anmeldung):**
- Benutzername: `Robin12345`
- Passwort: `Nimbus!2024`

**Option 2 (SQL-Injection im Passwort):**
- Benutzername: `Robin12345`
- Passwort: Eine SQL-Injection Payload (siehe unten)

**Option 3 (SQL-Injection im Benutzernamen):**
- Benutzername: `Robin12345' OR '1'='1` (oder andere Variante)
- Passwort: (egal, kann leer sein)

**Beispiel SQL-Injection Payloads:**
  - `' OR '1'='1`
  - `' OR 1=1--`
  - `admin'--`
  - `' OR 'x'='x`
  - `" OR "1"="1`
  - `' OR true--`
  - Und viele weitere SQL-Injection Varianten!

---

**Viel Spaß! 🎉**
