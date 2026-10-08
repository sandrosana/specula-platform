# Specula Threat – Piano di implementazione dell'MVP

> Stato: **APPROVATO – v1.0** (05/10/2026)
> Riferimenti: [specifica-funzionale-dashboard.md](specifica-funzionale-dashboard.md) (v1.2) · [architettura.md](architettura.md) (v1.2) · [identita-visiva.md](identita-visiva.md)

---

## 1. Regole valide per tutte le milestone

**Definizione di "completato"**, comune a ogni PR:
- CI verde (ruff, mypy, pytest; dal M5 anche il frontend), senza controlli disattivati o saltati.
- Test per ogni comportamento nuovo, secondo le regole di [CLAUDE.md](../CLAUDE.md): fixture registrate per i collector, test RBAC per gli endpoint.
- Variabili nuove aggiunte a `.env.example`; documentazione aggiornata nella stessa PR se cambia qualcosa di descritto nei documenti approvati (con nuova approvazione).
- **Verifica sulla VM del LAB** per tutto ciò che va eseguito: la workstation Windows non ha Docker, Node né Python affidabile, quindi "funziona" significa verificato sulla VM o in CI.

**PR:** piccole e focalizzate (un collector o una funzione per PR), branch `m<N>/<descrizione>` (es. `m2/cisa-kev-collector`), merge su `main` solo tramite PR.

**Ordine:** una milestone inizia solo quando la precedente ha soddisfatto il suo criterio di completamento. Dentro una milestone, le PR seguono l'ordine indicato.

## 2. Panoramica

| Milestone | Obiettivo | Prerequisiti |
|-----------|-----------|--------------|
| **M0** | Rename in `specula-platform`, pulizia legacy e documentazione nel repository | Accesso in scrittura a GitHub dalla workstation |
| **M1** | Scheletro: compose, FastAPI, DB, Alembic, config, CI, backup | Decisioni §11 #12 e #14 prese (certificato autofirmato, disco di backup dedicato); VM Debian del LAB (10.128.4.106) pronta con Docker e il disco di backup montato |
| **M2** | Framework collector + CISA KEV end-to-end, `GET /kev`, `GET /sources` | M1 |
| **M3** | NVD, EPSS, livelli di priorità P1–P4 | M2; chiave NVD consigliata |
| **M4** | Autenticazione, ruoli, abilitazioni e filtri per classe | M3 |
| **M5** | Frontend base: login, KPI 1–5, vista Fonti, pagine CVE/KEV | M4; `docs/identita-visiva.md` approvato |
| **M6** | ransomware.live (API PRO) e vittime come entità con avvistamenti | M5; quota verificata e T&C accettati; chiave PRO |
| **M7** | Fonti IOC: abuse.ch, AlienVault OTX, CSIRT Italia | M6; decisioni §11 #9 e #10 |
| **M8** | Intel feed | M7 |
| **M9** | Mappa, pannelli rimanenti, ricerca globale, esportazioni | M8 |
| **M10** | Dashboard di argomento e topic personalizzati | M9 |
| **M11** | Chiusura MVP: criteri di accettazione, hardening, rilascio | M10 |

---

## M0 – Rename, pulizia legacy e documentazione

**Obiettivo.** Partire da un repository `specula-platform` che contiene solo la piattaforma Specula e la sua documentazione, senza perdere la storia degli script.

**Contenuto**
- **Rename del repository** da `osint-toolkit` a `specula-platform`. È un'operazione del proprietario su GitHub (Settings → General → Repository name). GitHub mantiene un redirect dal vecchio nome, ma i remote vanno aggiornati comunque.
- **Aggiornamento del remote** nella copia locale e in ogni altro clone (es. sulla VM del LAB):
  `git remote set-url origin https://github.com/sandrosana/specula-platform.git`.
  La cartella locale può essere rinominata a piacere: il nome della cartella non incide sul progetto compose, che è fissato a `specula` nel file compose.
- Tag annotato `legacy-final` sul commit attuale di `main` (`f81cec5`), pubblicato su GitHub.
- Documenti approvati (specifica, architettura, identità visiva quando approvata, questo piano, `CLAUDE.md`) su `main`.
- Eliminazione di `scripts/`, `templates/`, `install.sh`.
- File `LICENSE` (MIT, titolare Sandro Sana).
- README riscritto con il nome **Specula**: Specula come piattaforma, Specula Threat come modulo attuale, moduli futuri (Exposure, Third Party, OSINT, CLOSINT), stato del progetto, link ai documenti, riferimento al tag `legacy-final` per i vecchi script "OSINT Toolkit".
- `.gitignore` con `.env`, artefatti Python e Node, dump di backup.

**PR e operazioni previste**
1. Rename del repository su GitHub e aggiornamento dei remote (operazione del proprietario, non una PR).
2. `m0/docs` – specifica, architettura, piano, `CLAUDE.md`.
3. Creazione e push del tag `legacy-final` (operazione git, non una PR), **prima** del merge della PR 4.
4. `m0/remove-legacy` – rimozione script, `LICENSE`, README Specula, `.gitignore`.

**Criterio di completamento**
- Il repository si chiama `specula-platform`; `git remote -v` della copia locale punta al nuovo URL.
- Il tag `legacy-final` è visibile su GitHub e punta a `f81cec5`.
- Su `main` non ci sono più gli script legacy; GitHub riconosce la licenza MIT.
- Il README presenta Specula e Specula Threat e rimanda ai documenti e al tag.

**Note.** Per il rename, il push del tag e le PR serve l'autenticazione a GitHub dalla workstation (la GitHub CLI non è installata): il login va fatto dal proprietario.

---

## M1 – Scheletro

**Obiettivo.** Avere sulla VM del LAB una piattaforma vuota ma completa nella struttura: avviabile con un comando, raggiungibile in HTTPS, con database versionato, CI attiva e backup funzionante.

**Contenuto**
- Backend: `pyproject.toml` con lockfile (`uv`), struttura `backend/app/` dell'architettura §4, app factory FastAPI, `GET /api/v1/health` (liveness) e `/health/ready` (verifica del DB), logging strutturato.
- Configurazione con pydantic-settings, validata all'avvio; `.env.example` completo per le variabili note.
- SQLAlchemy async + Alembic: migrazione iniziale con il tipo `classification` (`public` | `internal` | `sensitive`) e la regola del default `sensitive` pronta per tutte le tabelle successive.
- CI GitHub Actions (architettura §14): `backend-lint`, `backend-types`, `backend-test` con PostgreSQL di servizio, `images`.
- Docker: immagine Python unica (entrypoint `api` e `scheduler`), compose con `proxy` (Caddy), `api`, `scheduler` (per ora vuoto), `db`, `backup`.
- Caddy con certificato autofirmato dalla propria CA locale (`tls internal`, decisione #12) e, **fino a M4**, accesso limitato (allowlist IP del LAB o autenticazione di base sul proxy), perché l'API non ha ancora login.
- Backup (architettura §15): container `backup`, cifratura, retention, destinazione esterna, `docs/runbook-backup.md`, script `verify-restore.sh`.

**PR previste**
1. `m1/backend-skeleton-ci` – scheletro backend, config, health, test, configurazione di ruff e mypy **e workflow CI**, così tutte le PR successive sono già verificate.
2. `m1/database` – SQLAlchemy, Alembic, migrazione iniziale, fixture DB per i test.
3. `m1/compose` – Dockerfile, compose, Caddyfile, job `images` in CI.
4. `m1/backup` – container di backup, runbook, script di verifica del ripristino.

**Criterio di completamento**
- CI verde su tutte le PR; branch protection attiva su `main` (impostazione del proprietario).
- Sulla VM: `docker compose up -d` avvia tutti i container; `https://<host>/api/v1/health/ready` risponde OK solo dagli indirizzi consentiti.
- `alembic upgrade head` e `alembic downgrade base` funzionano su un DB vuoto.
- Un backup cifrato compare sullo storage esterno; la **prima prova di ripristino** è eseguita e registrata nel runbook.

---

## M2 – Framework collector e CISA KEV end-to-end

**Obiettivo.** Dimostrare l'intero percorso dati su una fonte semplice: raccolta pianificata → cache → normalizzazione → upsert → API, con lo stato della fonte visibile.

**Contenuto**
- `collectors/base.py`: `CollectorBase`, `PeriodicCollector`, `SourceLicense`, tipi comuni. `ListenerCollector` definito come interfaccia, senza supervisor (roadmap).
- `collectors/http.py`: client condiviso con cache TTL su `http_cache`, richieste condizionali, rate limit, conteggio quote su `source_usage`, retry, supporto `HTTPS_PROXY`.
- `registry.py`, `runner.py`: abilitazione su `required_settings`, advisory lock, `collector_runs`, `collector_state` (cursori), upsert idempotente, assegnazione della classe, gestione dei fallimenti.
- Catena di post-processing inline (interfaccia, senza processori ancora).
- Scheduler APScheduler e CLI `python -m app.collectors run <name> [--full] [--no-cache]`.
- Collector `cisa_kev`, tabella `kev_entries`, fixture registrate.
- API: `GET /api/v1/kev` (filtri, paginazione a cursore) e `GET /api/v1/sources` (stato, ultimo run, licenza, uso).

**PR previste**
1. `m2/collector-framework` – base, client HTTP, cache, rate limit, quote, modelli e migrazioni di supporto.
2. `m2/runner-scheduler` – runner, lock, run tracking, scheduler, CLI.
3. `m2/cisa-kev-collector` – collector, modello, migrazione, test.
4. `m2/api-kev-sources` – endpoint e test.

**Criterio di completamento**
- Sulla VM lo scheduler esegue `cisa_kev` secondo la schedule; il numero di righe in `kev_entries` coincide con il numero di voci del feed ufficiale.
- Un secondo run entro il TTL non fa chiamate di rete (verificabile da `source_usage` e dai log); un run ripetuto non crea duplicati.
- Un errore di rete simulato chiude il run come `failed` senza avanzare il cursore (test).
- `COLLECTOR_CISA_KEV_ENABLED=false` disabilita il collector e `GET /sources` lo mostra come tale.
- `GET /sources` restituisce licenza, uso commerciale "Sì", `verified_on` e consumo.

---

## M3 – NVD, EPSS e livelli di priorità

**Obiettivo.** Avere il dataset vulnerabilità completo e l'ordinamento P1–P4 con motivo.

**Contenuto**
- Collector `nvd`: incrementale su `lastModStartDate`/`lastModEndDate`, paginazione, rate limit con e senza chiave, backfill da CLI, testo di attribuzione nei metadati di licenza; tabelle `vulnerabilities`, `vulnerability_products`.
- Collector `epss`: bulk CSV giornaliero, storico in `epss_scores`.
- Post-processor inline per il livello di priorità (specifica §6): `priority_level` e `priority_reason`, ricalcolati quando cambiano KEV o EPSS.
- API: `GET /cves` (ordinabile per livello, filtri), `GET /cves/{cve_id}`.

**PR previste**
1. `m3/nvd-collector`
2. `m3/epss-collector`
3. `m3/priority-levels`
4. `m3/api-cves`

**Criterio di completamento**
- Il backfill NVD completo termina sulla VM entro i limiti di rate (durata annotata nel PR); i run incrementali successivi aggiornano solo le CVE modificate.
- Verifica a campione: 3 CVE in KEV con uso ransomware risultano P1 con motivo corretto, 3 CVE con solo EPSS alto risultano P3.
- Criterio di accettazione 9 della specifica soddisfatto via API.
- La verifica di testo e limiti NVD sulla documentazione ufficiale è annotata in `verified_on`.

---

## M4 – Autenticazione, ruoli e filtri per classe

**Obiettivo.** Rendere la piattaforma utilizzabile in sicurezza da un team: chi accede, cosa può fare, cosa può vedere.

**Contenuto**
- Utenti locali (argon2), login/logout, cookie di sessione HttpOnly, CSRF token, `GET /auth/me`; comando CLI per creare il primo Admin.
- Ruoli Viewer / Analyst / Admin con dipendenze FastAPI su ogni endpoint di scrittura.
- Abilitazioni `user_grants` (`class:internal`, `class:sensitive`, `source:<nome>`).
- Filtro per classe nel livello di repository, applicato a tutte le letture; impostazione degli aggregati per classe.
- `audit_log` per modifiche, run forzati e letture di dati `sensitive`.
- API admin: utenti e abilitazioni, `POST /admin/collectors/{name}/run`, `GET /admin/system` (stato backup).
- Rimozione della restrizione temporanea sul proxy.

**PR previste**
1. `m4/local-auth`
2. `m4/roles-audit`
3. `m4/classification-filters`
4. `m4/admin-api`

**Criterio di completamento**
- Ogni endpoint ha un test con un ruolo non autorizzato che riceve 403.
- Un test con righe `sensitive` di prova dimostra che un utente senza abilitazione non le vede **né negli elenchi né nei conteggi**; lo stesso vale per un Admin senza abilitazione esplicita.
- Una riga inserita senza classe risulta `sensitive` (test).
- Run forzato e modifiche agli utenti compaiono nell'audit log (criterio di accettazione 6).

---

## M5 – Frontend base con KPI

**Obiettivo.** Prima versione utilizzabile dagli analisti: login, KPI sulle fonti disponibili, vista Fonti e consultazione delle vulnerabilità.

**Prerequisito:** [docs/identita-visiva.md](identita-visiva.md) approvato (v1.0, 05/10/2026: prerequisito soddisfatto). Restano aperti, senza bloccare M5, la verifica di `tnum` nella build e il marchio vettoriale definitivo, per cui fino al suo arrivo si usa un segnaposto (§10 del documento).

**Contenuto**
- Progetto React + TypeScript + Vite, client generato da OpenAPI, i18n italiano, container `frontend` e job CI `frontend`.
- Design token di `identita-visiva.md` come unica fonte di colori, font e stili di severità; tema scuro (default) e chiaro.
- Login, layout, selettore di periodo, indicatore di freschezza.
- Viste materializzate per i KPI (per giorno e per classe) e `GET /dashboard/kpis`.
- KPI 1–5 (NVD, KEV, EPSS). I KPI 6–8 mostrano lo stato "fonte non ancora disponibile", come previsto dal degrado controllato.
- Vista Fonti (specifica §4.6) con licenza, uso commerciale, quota, classe e, per gli Admin, storico run e stato del backup.
- Pagine elenco e dettaglio CVE (con livello e motivo) ed elenco KEV.

**PR previste**
1. `m5/frontend-scaffold` – progetto, CI, container.
2. `m5/auth-layout`
3. `m5/kpi-api` – viste materializzate e endpoint.
4. `m5/kpi-ui` – tile KPI e selettore di periodo.
5. `m5/sources-view`
6. `m5/cve-kev-pages`

**Criterio di completamento**
- Criteri di accettazione 3 e 4 della specifica soddisfatti per i KPI 1–5.
- La dashboard si carica in meno di 2 secondi a cache calda sulla VM.
- Un Viewer vede la vista Fonti senza i comandi Admin; un Admin vede storico run e stato backup.
- Un test automatico verifica che le coppie testo/sfondo dei token rispettino il contrasto AA dichiarato in `identita-visiva.md`; nessun colore è definito fuori dai token.

---

## M6 – ransomware.live e vittime

**Obiettivo.** Introdurre il modello vittima/avvistamenti con la prima fonte ransomware.

**Prerequisiti:** quota dell'API PRO riverificata sulla pagina ufficiale e nei T&C (valori discordanti: 500.000/mese e 3.000/giorno), T&C letti e accettati, chiave PRO disponibile.

**Contenuto**
- Normalizzazione di nome azienda e dominio (Public Suffix List), tabella `generic_domains` con seed, regole di associazione e relazione `shared_domain` (architettura §8.2).
- Collector `ransomware_live` con `RANSOMWARE_LIVE_API_KEY` obbligatoria e limite di quota prudenziale finché la verifica non è chiusa.
- Tabelle `ransomware_groups`, `ransomware_victims`, `victim_sightings`, `victim_relations`, `aliases`.
- API ransomware e admin `merge` / `unmerge`; suggerimenti di unione.
- KPI 6–7, pannelli "Top gruppi ransomware" e "Settori colpiti".

**PR previste**
1. `m6/victim-normalization` – normalizzazione, domini generici, regole di associazione (logica pura e test).
2. `m6/ransomware-live-collector`
3. `m6/api-ransomware-merge`
4. `m6/ui-ransomware`

**Criterio di completamento**
- Criterio di accettazione 8: senza chiave il collector è disabilitato e l'API v2 gratuita non viene mai chiamata (test).
- Test delle regole di associazione, inclusi i casi di dominio generico e di società diverse con lo stesso dominio.
- Il limite di quota configurato viene rispettato (test del client HTTP).
- La quota verificata è riportata in `SourceLicense` e nella tabella §6.2 dell'architettura.

---

## M7 – Fonti IOC: abuse.ch, AlienVault OTX, CSIRT Italia

**Obiettivo.** Completare le fonti MVP con indicatori, pulse e avvisi.

**Prerequisiti:** decisione §11 #9 (uso delle fonti "Da verificare") e #10 (CSIRT Italia) prese; chiavi `ABUSECH_AUTH_KEY` e `OTX_API_KEY`.

**Contenuto**
- Tabelle `indicators`, `indicator_sightings`, mappatura TLP → classe (architettura §10.2).
- Collector `abusech.urlhaus`, `abusech.threatfox`, `abusech.malwarebazaar`, `abusech.feodo`.
- Collector `otx` e tabella `pulses`.
- Collector `csirt_it.misp` (tabella `misp_events`) e `csirt_it.rss` (tabella `advisories`, post-processor di estrazione delle CVE, solo titolo/link/data/CVE finché vale la decisione #10).
- KPI 8 e pannelli "Famiglie malware", "IOC per tipo e fonte", "Bollettini CSIRT Italia", "Pulse OTX recenti".

**PR previste**
1. `m7/indicators-model`
2. `m7/abusech-collectors` (una PR per sotto-fonte se diventano grandi)
3. `m7/otx-collector`
4. `m7/csirt-it-collectors`
5. `m7/ui-ioc-panels`

**Criterio di completamento**
- Un IOC presente in più fonti è una sola entità con più avvistamenti.
- Un evento MISP con TLP diverso da CLEAR riceve la classe corretta; un TLP:RED non viene acquisito (test).
- La vista Fonti mostra abuse.ch, OTX e CSIRT Italia come "Da verificare" (criterio di accettazione 7).

---

## M8 – Intel feed

**Obiettivo.** Lo stream unificato degli eventi, con regole di severità e anti-rumore.

**Contenuto**
- Tabella `events`, generazione degli eventi nel runner per tutti i tipi della specifica §4.5, dedup, aggregazione `ioc.batch`, aggiornamento degli eventi per le vittime segnalate da più fonti.
- Script per generare gli eventi dai dati già raccolti.
- `GET /feed` con filtri e paginazione a cursore; UI del feed (dashboard e pagina intera), filtri nell'URL, polling ogni 60 secondi.

**PR previste**
1. `m8/events-generation`
2. `m8/api-feed`
3. `m8/ui-feed`

**Criterio di completamento**
- Test per ogni tipo di evento e per le regole anti-rumore (una CVE che entra in KEV produce un solo evento; una vittima da due fonti è un solo evento, criterio di accettazione 10).
- Un evento collegato a un'entità `sensitive` non è visibile a chi non ha l'abilitazione.

---

## M9 – Mappa, pannelli rimanenti, ricerca ed esportazioni

**Obiettivo.** Completare la dashboard globale.

**Contenuto**
- Mappa con i due livelli (vittime, infrastruttura), GeoLite2 opzionale con `MAXMIND_LICENSE_KEY`, pannello laterale per paese, paese di interesse evidenziato.
- Pannelli rimanenti ("CVE prioritarie", "Ultime KEV", "Top vendor/prodotti").
- Ricerca globale (`GET /search`).
- Esportazione CSV degli elenchi e PNG dei grafici.

**PR previste**
1. `m9/map-api`
2. `m9/map-ui`
3. `m9/remaining-panels`
4. `m9/search-export`

**Criterio di completamento**
- Ogni numero, barra e paese porta all'elenco filtrato corrispondente (criterio di accettazione 3 esteso a tutta la dashboard).
- Senza `MAXMIND_LICENSE_KEY` la mappa infrastruttura usa solo il paese della fonte, senza errori.

---

## M10 – Dashboard di argomento e topic

**Obiettivo.** Le viste per vendor, CVE, gruppo, famiglia, paese, settore e i topic personalizzati.

**Contenuto**
- `GET /topics/{kind}/{key}/dashboard` per i sei tipi predefiniti e relative pagine.
- Topic personalizzati: CRUD, criteri (AND tra categorie, OR dentro la categoria), anteprima dei risultati, visibilità privata o condivisa, "segui".
- Evidenziazione nel feed globale degli eventi dei topic seguiti.

**PR previste**
1. `m10/topic-dashboards-api`
2. `m10/topic-dashboards-ui`
3. `m10/custom-topics`
4. `m10/follow-highlight`

**Criterio di completamento**
- Criterio di accettazione 5: un Analyst crea "Sanità Italia", lo condivide, un Viewer lo vede e il feed evidenzia gli eventi per chi lo segue.

---

## M11 – Chiusura MVP

**Obiettivo.** Verificare che l'MVP rispetti la specifica e rilasciarlo.

**Contenuto**
- Verifica di tutti i criteri di accettazione della specifica §9 sulla VM, con esito documentato.
- Revisione di sicurezza del codice (`/security-review`) e correzioni.
- Verifica delle prestazioni a cache calda.
- Nuova prova di ripristino del backup con dati reali, registrata nel runbook.
- Documentazione operativa: installazione sulla VM, aggiornamento, rotazione delle chiavi.
- Tag di rilascio `v1.0.0`.

**PR previste**
1. `m11/acceptance-fixes` (una o più, in base a ciò che emerge)
2. `m11/ops-docs`

**Criterio di completamento**
- Tutti i criteri di accettazione 1–10 superati e documentati.
- Nessuna vulnerabilità alta o critica aperta dalla revisione di sicurezza.
- Prova di ripristino registrata; tag `v1.0.0` pubblicato.

---

## 3. Dopo l'MVP

In ordine, come da decisioni approvate:
1. **Entra ID (OIDC)**, primo sviluppo successivo (decisione #6).
2. Fonti e funzioni della roadmap (architettura §13): Tenable.ONE, Ransomfeed, Telegram, arricchimento AI ibrido. Ognuna con una specifica dedicata da approvare prima dell'implementazione.
3. Moduli fuori ambito della specifica §8 (Third-Party Risk, briefing AI, notifiche, …), da pianificare separatamente.
