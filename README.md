# Proxmox Patchlevel Scanner

Automatisk verktøy som henter patchstatus fra et Proxmox VE-miljø og lagrer en JSON-rapport per kjøring.

## Viktig

**Dette verktøyet installerer ikke oppdateringer.** Det leser kun tilgjengelige pakkeversjoner via Proxmox API og rapporterer status.

**Ikke kjør mot produksjon uten godkjenning fra IT-sjef.** Bruk kun testmiljø i prosjektperioden med mindre du har eksplisitt tillatelse.

**Bruk et API-token med minst mulig rettigheter** (read-only der det er mulig). Lagre token i `.env` — aldri i kildekode eller versjonskontroll.

## Kravdekning

| Krav | Beskrivelse | Status |
|------|-------------|--------|
| F-01 | Hente alle noder automatisk | Ja |
| F-02 | Hente pakkeoppdateringer per node | Ja |
| F-03 | Skille security/ordinary | Ja, best-effort (se nedenfor) |
| F-04 | Lagre JSON automatisk ved kjøring | Ja |
| F-05 | Vise utilgjengelig node uten stille feil | Ja |
| NF-01 | Ingen passord i kode | Ja — token i `.env` |
| NF-02 | Full skanning under 60 sek | Ja — `duration_seconds` i rapport |
| NF-03 | README + versjonskontroll | Ja — denne filen + Git |
| NF-04 | Planlagt kjøring dokumentert | Ja — cron-eksempel nedenfor |

### F-03 — Security vs ordinary (best-effort)

Security classification is best-effort based on package metadata/source text. Verktøyet markerer pakker som `security` når metadata peker mot Debian security-kilder (f.eks. `Origin: Debian-Security`). Det er **ikke** perfekt sikkerhetsdeteksjon — pakker uten tydelig metadata kan feilklassifiseres.

### NF-01 — Ingen passord i kode (akseptansekriterium)

Autentisering skjer **kun via Proxmox API-token** lastet fra miljøvariabler. Ingen passord eller token-secrets finnes i kildekoden.

| Kontroll | Hvordan det er ivaretatt |
|----------|--------------------------|
| Ingen hemmeligheter i `scanner.py` / `config.py` | Token hentes med `os.getenv()` |
| Hemmeligheter kun lokalt | Fylles inn i `.env` (gitignored) |
| Mal uten secrets | `.env.example` har kun `PASTE_SECRET_HERE` |
| Versjonskontroll | `.env` committes aldri (se `.gitignore`) |

Opprett token i Proxmox (Datacenter → Permissions → API Tokens). Bruk minst mulig rettigheter (`Sys.Audit` + lesing av noder).

### NF-02 — Kjøretid under 60 sekunder (akseptansekriterium)

Verifisert ved kjøring mot testmiljø med **flere noder** (ett eller flere Proxmox-hosts):

| Måling | Verdi |
|--------|-------|
| Noder skannet | Alle noder oppdaget via API |
| Kjøretid | **2,16 sekunder** (`duration_seconds` i rapport, eksempel med 2 noder) |
| Krav | < 60 sekunder — **oppfylt** |

Bevis ligger i JSON-rapporten (`start_time`, `end_time`, `duration_seconds`) og terminaloutput ved kjøring. Kjør `python scanner.py` på nytt for å generere fersk rapport.

### NF-03 — Versjonskontroll og README (akseptansekriterium)

Kildekoden ligger i Git. En ny person skal kunne sette opp og kjøre verktøyet **kun** ved å følge denne READMEen — se [Oppsett (ny bruker)](#oppsett-ny-bruker) og [Kjøring](#kjøring) nedenfor.

### NF-04 — Planlagt kjøring på Linux (akseptansekriterium)

Verktøyet kan kjøres automatisk med cron. Full oppsett på Linux-server:

**1. Installer avhengigheter**

```bash
sudo apt update
sudo apt install -y python3 python3-pip git
```

**2. Legg prosjektet på serveren**

```bash
sudo mkdir -p /opt/proxmox-patchscanner
sudo chown $USER:$USER /opt/proxmox-patchscanner
git clone <repo-url> /opt/proxmox-patchscanner
cd /opt/proxmox-patchscanner
pip3 install -r requirements.txt
```

**3. Konfigurer token (samme som lokalt oppsett)**

```bash
cp .env.example .env
nano .env   # fyll inn PROXMOX_HOST, token og eventuelle PROXMOX_HOST_2, _3, ...
chmod 600 .env
```

**4. Test manuelt**

```bash
python3 scanner.py
```

**5. Legg inn ukentlig cron-jobb**

```bash
crontab -e
```

Legg til (mandager kl. 08:00):

```cron
0 8 * * 1 cd /opt/proxmox-patchscanner && /usr/bin/python3 scanner.py >> /var/log/patchscanner.log 2>&1
```

**6. (Valgfritt) Opprett loggfil med riktige rettigheter**

```bash
sudo touch /var/log/patchscanner.log
sudo chown $USER:$USER /var/log/patchscanner.log
```

Rapporter lagres automatisk i `reports/` med tidsstempel i filnavn.

## Forutsetninger

- Python 3.10+
- Nettverkstilgang til Proxmox API (port 8006)
- Proxmox API-token med lesetilgang til noder og APT-informasjon

## Oppsett (ny bruker)

1. **Klon repoet**

   ```bash
   git clone <repo-url>
   cd proxmox-patchscanner
   ```

2. **Installer avhengigheter**

   ```bash
   pip install -r requirements.txt
   ```

3. **Konfigurer miljøvariabler**

   ```bash
   cp .env.example .env
   ```

   Rediger `.env`:

   | Variabel | Beskrivelse |
   |----------|-------------|
   | `PROXMOX_HOST` | Proxmox URL, f.eks. `https://192.168.1.10:8006` |
   | `PROXMOX_TOKEN_ID` | Token ID, f.eks. `root@pam!patchscanner` |
   | `PROXMOX_TOKEN_SECRET` | Token secret |
   | `PROXMOX_HOST_2`, `_3`, `_4`, … | *(Valgfritt)* Flere Proxmox-hosts — legg til så mange du trenger |
   | `PROXMOX_TOKEN_ID_2`, `_3`, … | Token ID for hver ekstra host |
   | `PROXMOX_TOKEN_SECRET_2`, `_3`, … | Token secret for hver ekstra host |
   | `VERIFY_SSL` | `true` eller `false` (testmiljø med self-signed cert) |
   | `OUTPUT_DIR` | Mappe for rapporter (standard: `reports`) |
   | `TIMEOUT_SECONDS` | API-timeout (standard: 20) |

   **Flere noder:** Hver `PROXMOX_HOST` er ett API-endepunkt (cluster). Skanneren henter **alle noder** fra hvert cluster automatisk via `/nodes`. For tre separate hosts setter du `PROXMOX_HOST`, `PROXMOX_HOST_2` og `PROXMOX_HOST_3` med tilhørende tokens. For ett cluster med flere noder trenger du bare én `PROXMOX_HOST` — alle noder i clusteret inkluderes.

4. **Opprett API-token i Proxmox**

   Datacenter → Permissions → API Tokens → Add  
   Gi kun nødvendige rettigheter for lesing av noder og pakkeinfo.

## Kjøring

```bash
python scanner.py
```

Forventet terminaloutput:

```
Report saved: reports/patch_report_2026-06-13_18-03-06.json
Duration: 2.37 seconds
Hosts scanned: 2 (2 node(s) total)
{
    "nodes_total": 2,
    "nodes_online": 2,
    ...
}
```

Antall noder avhenger av miljøet — eksempelet over er fra et oppsett med to hosts/noder.

Ta **skjermbilde av denne outputen** til teknisk rapport / muntlig gjennomgang.

## JSON-rapport

Hver kjøring lagrer en tidsstemplet fil i `reports/`.

Viktige felt:

| Felt | Betydning |
|------|-----------|
| `start_time` / `end_time` | Når skanningen startet og sluttet |
| `duration_seconds` | Total kjøretid (NF-02-bevis) |
| `proxmox_hosts` | Alle hosts som ble skannet |
| `security_classification_note` | Forklarer best-effort security-klassifisering |
| `summary` | Aggregert oversikt over noder og oppdateringer |
| `nodes[].cluster_host` | Hvilken Proxmox-host noden tilhører |
| `nodes[].reachable` | `false` hvis node ikke kunne skannes (F-05) |
| `nodes[].packages[]` | Pakkenavn, nåværende versjon, tilgjengelig versjon, type |

## Elasticsearch + Kibana

Skanneren kan automatisk sende JSON-rapporter til Elasticsearch, og du visualiserer data i Kibana.

**Dataflyt:** `Python scanner` → `JSON-rapport` → `Elasticsearch` → `Kibana dashboard`

### Hva dashboardet viser

| Visualisering | Kilde | Beskrivelse |
|---------------|-------|-------------|
| Scan History — Compare All Reports | `patchscanner-scans` | Tabell: én rad per rapport med online/failed/updates/security/duration |
| Total Scan Runs | `patchscanner-scans` | Antall indekserte rapporter fra `reports/` |
| Total Updates per Scan | `patchscanner-scans` | Linjediagram — sammenlign oppdateringer på tvers av kjøringer |
| Security vs Ordinary per Scan | `patchscanner-scans` | Trend for security/ordinary per rapport |
| Node Health per Scan | `patchscanner-scans` | Online vs failed noder per rapport |
| Node Detail per Scan | `patchscanner-nodes` | Per node, per host, per skanning |
| Updates per Node over Time | `patchscanner-nodes` | Hver node sporet på tvers av rapporter |
| Updates per Proxmox Host over Time | `patchscanner-nodes` | `cluster_host` sammenlignet over tid |
| Package Versions per Scan | `patchscanner-packages` | Pakkenavn, versjoner, node, host, type |
| Top Packages | `patchscanner-packages` | Mest rapporterte pakker på tvers av historikk |

### 1. Start Elasticsearch og Kibana (Docker)

Krever [Docker Desktop](https://www.docker.com/products/docker-desktop/) eller Docker Engine.

```bash
docker compose up -d
```

- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601

Vent til begge er klare (ca. 1–2 minutter første gang).

### 2. Aktiver Elasticsearch-eksport

Legg til i `.env`:

```env
ELASTICSEARCH_ENABLED=true
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_INDEX_PREFIX=patchscanner
```

### 3. Kjør skanner eller importer eksisterende rapporter

**Ny skanning** (lagrer JSON og pusher til ES):

```bash
python scanner.py
```

**Importer tidligere rapporter** fra `reports/`:

```bash
python scripts/import_reports.py
```

### 4. Sett opp Kibana-dashboard

```bash
pip install requests
python scripts/setup_kibana.py
```

Åpne deretter Kibana → **Dashboards** → **Proxmox Patch Scanner**.

Scriptet oppretter tre data views (`patchscanner-scans`, `patchscanner-nodes`, `patchscanner-packages`) og importerer ferdig dashboard fra `kibana/dashboard.ndjson`.

### Elasticsearch-indekser

| Indeks | Innhold |
|--------|---------|
| `patchscanner-scans` | Én dokument per skanning (summary, duration, tidsstempel) |
| `patchscanner-nodes` | Én dokument per node per skanning (`cluster_host`, status, antall oppdateringer) |
| `patchscanner-packages` | Én dokument per pakke per node per skanning (for topplister og security/ordinary) |

### Planlagt kjøring med ES

Utvid cron-jobb fra NF-04 med `ELASTICSEARCH_ENABLED=true` i `.env` på serveren. Hver ukentlig kjøring bygger automatisk opp historikk i Kibana.

### Automatisk skanning + Kibana (bash)

Én kommando starter stacken, kjører skanning, verifiserer nodehelse, pusher til Elasticsearch og åpner dashboardet:

```bash
chmod +x scripts/scan_and_analyze.sh
./scripts/scan_and_analyze.sh
```

Scriptet gjør følgende:

1. Starter `docker compose` hvis Elasticsearch ikke kjører
2. Venter til Elasticsearch og Kibana er klare
3. Installerer Kibana-dashboard første gang (hvis det mangler)
4. Kjører `scanner.py` med node-helsesjekk (valgfritt `EXPECTED_NODES`)
5. Åpner **Proxmox Patch Scanner**-dashboardet i nettleseren

**Node-helsesjekk** — etter hver skanning skrives status per node:

```
Node health:
  [OK] pve @ https://83.108.147.197:8006 — status=online, updates=58
  [OK] pve @ https://10.0.0.81:8006 — status=online, updates=58

All 2 node(s) are online and reachable.
```

(Eksempel med to noder — meldingen viser faktisk antall oppdagede noder.)

Hvis en node er nede, feiler scriptet med exit code 1 (nyttig for cron-varsling).

**Miljøvariabler** (`.env`):

| Variabel | Standard | Beskrivelse |
|----------|----------|-------------|
| `EXPECTED_NODES` | *(tom)* | Valgfritt — feil hvis antall oppdagede noder avviker. Utelat for å akseptere alle |
| `KIBANA_URL` | `http://localhost:5601` | Kibana-base-URL — **must use `http://`**, not `https://` |
| `KIBANA_DASHBOARD_ID` | `ps-dashboard-main` | Dashboard-ID å åpne |
| `OPEN_BROWSER` | `true` | Sett `false` på headless server / cron |
| `SKIP_DOCKER` | `false` | Sett `true` hvis ES/Kibana kjører et annet sted |
| `NO_PAUSE` | `false` | Sett `true` for cron — hopper over «Press Enter» på slutten |

All output lagres også i **`logs/scan_and_analyze.log`** — åpne den filen hvis terminalen lukker for fort.

**Cron-eksempel** (ukentlig skanning uten nettleser):

```cron
0 8 * * 1 cd /opt/proxmox-patchscanner && OPEN_BROWSER=false ./scripts/scan_and_analyze.sh >> /var/log/patchscanner.log 2>&1
```

På Windows (Git Bash / WSL): samme kommando fungerer; nettleseren åpnes via `cmd.exe` eller `explorer.exe`.

### Feilsøking (Elasticsearch / Kibana)

| Problem | Løsning |
|---------|---------|
| `Elasticsearch export failed: Connection refused` | Kjør `docker compose up -d` og vent til port 9200 svarer |
| Tomt dashboard | Kjør `python scripts/import_reports.py` eller `python scanner.py` med ES aktivert |
| `Kibana setup failed` | Vent litt lenger og kjør `python scripts/setup_kibana.py` på nytt |
| Duplikat data views | Scriptet hopper over eksisterende views; bruk `overwrite=true` ved re-import av dashboard |

## Prosjektstruktur

```
proxmox-patchscanner/
├── scanner.py
├── config.py
├── elastic_export.py
├── docker-compose.yml
├── requirements.txt
├── .env.example
├── scripts/
│   ├── import_reports.py
│   ├── build_dashboard.py
│   ├── setup_kibana.py
│   └── scan_and_analyze.sh
├── kibana/
│   └── dashboard.ndjson
├── reports/
└── README.md
```

## Versjonskontroll (NF-03)

Prosjektet ligger i Git. `.env` og genererte rapporter committes **aldri** (se `.gitignore`).

```bash
git clone <repo-url>
cd proxmox-patchscanner
git log --oneline
```

## Feilsøking

| Problem | Løsning |
|---------|---------|
| `Missing required environment variables` | Sjekk at `.env` finnes og er utfylt |
| SSL-feil | Sett `VERIFY_SSL=false` kun i testmiljø |
| `401 Unauthorized` | Sjekk token ID og secret |
| `403 Permission check failed` | Token mangler `Sys.Audit` eller lesetilgang |
| Node markert `reachable: false` | Node offline eller API utilgjengelig — se `error`-feltet |
