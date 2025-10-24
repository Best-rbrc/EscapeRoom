# NimbusDrive Demo

Eine moderne Single-Page-Demo, die einen Cloud-Drive-Login mit simuliertem Support-Anruf und SQLi-Bypass demonstriert.

## Features
- Stilvolles Card-Layout mit Login-Formular (Benutzername & Passwort) und Call-to-Action-Bereich.
- "Benutzernamen vergessen?" öffnet ein Modal mit Support-Anruf (OpenAI Realtime API Integration + fallback Simulation).
- SQL-Injection-Bypass (rein simuliert, keine echte Datenbank) akzeptiert typische Payloads wie `' OR '1'='1`.
- Nach erfolgreichem Login erscheint ein Mock-Dateisystem mit dem Ordner **Wichtig/** und der Datei **VeryImportantFile.pdf**.

## Nutzung
1. Öffne `index.html` in einem aktuellen Browser.
2. Für den Support-Call kann ein OpenAI API-Key (Realtime) eingegeben werden. Ohne Key läuft eine Skript-Simulation.
3. Der Support verrät den Benutzernamen `Robin12345`. Das Passwort kann über eine SQLi-Payload umgangen werden.
4. Nach erfolgreicher Anmeldung steht das Dateibrowser-Interface zur Verfügung.

> **Hinweis:** Es wird niemals echtes SQL ausgeführt. Alle Effekte sind rein Frontend-basiert.

## Assets
- `assets/VeryImportantFile.pdf`: Dummy-PDF-Datei, die im Dateibrowser verlinkt ist.
