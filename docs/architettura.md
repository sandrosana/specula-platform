# Specula Threat – Architettura

> Stato: **BOZZA v1.5 – modifiche a §4, §6.1, §6.2, §8.2, §11, §13 in attesa di approvazione** (09/10/2026). La v1.4 resta approvata. Le decisioni ancora aperte sono elencate in §11.2.
> Prodotto: **Specula Threat**, modulo di Threat Intelligence della piattaforma **Specula** (moduli futuri: Exposure, Third Party, OSINT, CLOSINT). Repository: `specula-platform`.
> Documenti collegati: [specifica-funzionale-dashboard.md](specifica-funzionale-dashboard.md) · [identita-visiva.md](identita-visiva.md)
>
> Versioni: v1.0 approvazione iniziale · v1.1 modifica editoriale (nome del prodotto e del progetto compose), nessuna modifica tecnica · v1.2 ambiente LAB (Debian, IP, nessun proxy) e decisioni #12 (TLS) e #14 (backup) · v1.3 §15 dettagli di implementazione del backup (file marcatore, generazione della chiave, stato in file fino a M4, prova di ripristino in container) · v1.4 NVD ed EPSS verificati sulle fonti ufficiali (endpoint, limiti, licenze); EPSS: punteggio attuale più storico delle sole variazioni rilevanti, uso commerciale "Sì" con attribuzione · v1.5 Ransomfeed anticipato nell'MVP (M6) e verificato; roadmap: arricchimento on-demand (VirusTotal, Shodan) dopo il rilascio, monitor dei leak (IntelX, Dexpose) nel modulo Exposure, altre fonti candidate.

---

## 1. Principi

1. **API-first.** Il backend espone un'API REST versionata (`/api/v1`) con OpenAPI generato automaticamente. Il frontend React è un client come gli altri: tutto ciò che la UI mostra è ottenibile via API.
2. **Collector a plugin.** Ogni fonte è un modulo isolato che implementa un'interfaccia comune. Ci sono due tipi: **periodici** (eseguiti dallo scheduler) e **listener** (a esecuzione continua). Aggiungere una fonte significa aggiungere un modulo e una voce di configurazione, senza toccare API o UI.
3. **Separazione raccolta / consultazione.** I collector scrivono, l'API legge. Le richieste degli utenti non chiamano mai le fonti esterne.
4. **Rispetto delle fonti.** Rate limit, quote, licenze e caching sono gestiti dal framework dei collector. Ogni collector dichiara i metadati di licenza, visibili a tutti nella vista Fonti.
5. **Classificazione dei dati.** Ogni dato ha una classe (pubblico / interno / sensibile) e la visibilità è applicata nel backend, non solo nella UI.
6. **I dati di origine non si modificano.** Normalizzazione e arricchimento (anche AI) producono dati derivati, tracciati e separati dall'originale.
   La classe di un dato è assegnata dal collector al momento della raccolta. **Un dato senza classe è trattato come sensibile.**
7. **Configurazione da ambiente.** Segreti e parametri solo da variabili d'ambiente (`.env`). Nessuna chiave nel codice, nel database o nei log.
8. **Pochi componenti.** Nell'MVP: proxy, frontend, API, scheduler, PostgreSQL. Gli altri container arrivano con la roadmap (§13).

## 2. Vista d'insieme

```
                        ┌─────────────────────────────────────┐
   Browser ── HTTPS ──▶ │ proxy (Caddy)                       │
                        │  /        → frontend (React statico) │
                        │  /api/v1  → api                      │
                        └───────────────┬─────────────────────┘
                                        │
                     ┌──────────────────▼──────────────────┐
                     │ api  (FastAPI)                      │
                     │  auth · RBAC · classi · query       │
                     └──────────────────┬──────────────────┘
                                        │ lettura (filtrata per classe)
                     ┌──────────────────▼──────────────────┐
                     │ PostgreSQL 16                       │
                     │  entità · avvistamenti · eventi     │
                     │  cache HTTP · run · viste KPI       │
                     └───────▲──────────────────▲──────────┘
                             │ scrittura        │ scrittura
          ┌──────────────────┴───────┐   ┌──────┴────────────────────────┐
          │ scheduler (APScheduler)  │   │ listener-*  (roadmap)          │
          │  collector periodici     │   │  collector continui, es.       │
          │  + post-processing       │   │  Telegram in container isolato │
          └────────────┬─────────────┘   └──────┬────────────────────────┘
                       │                        │
                       ▼                        ▼
                fonti esterne (HTTP, cache TTL, rate limit, quote)

          ┌──────────────────────────┐   ┌───────────────────────────────┐
          │ enricher (roadmap)       │──▶│ llm (roadmap) – provider       │
          │  post-processing async   │   │  locale su CPU: tutte le classi│
          │  routing per classe      │   └───────────────────────────────┘
          │                          │──▶ provider remoto via API:
          └──────────────────────────┘    SOLO dati pubblici, con audit
```

**Progetto compose:** `specula` (`name: specula` in `deploy/docker-compose.yml`).
**Container MVP (docker compose):** `proxy`, `frontend`, `api`, `scheduler`, `db`, `backup` (§15).
**Container in roadmap:** `listener-telegram`, `enricher`, `llm` (provider locale su CPU).
`api`, `scheduler`, `listener-*` ed `enricher` usano **la stessa immagine Python** con entrypoint diversi.

## 3. Stack e ambiente

| Ambito | Scelta |
|--------|--------|
| Ambiente di esecuzione | **Macchina fisica** `cybertower` nel LAB Eurosystem, **Debian 13 (trixie)**, indirizzo **10.128.4.106**, 4 CPU, 7,6 GB di RAM, Docker Engine con plugin Compose. **Nessuna GPU**, **nessun proxy** per uscire verso internet. La macchina è **condivisa con altri utenti** (es. una condivisione Samba di un altro utente sul disco dati) |
| Linguaggio | Python 3.12 |
| API | FastAPI + Pydantic v2 |
| ORM / DB | SQLAlchemy 2.0 (async) + asyncpg, PostgreSQL 16 (estensioni `pg_trgm`, `unaccent`) |
| Migrazioni | Alembic |
| HTTP client | httpx (async) + tenacity; supporto a `HTTPS_PROXY`, non necessario nel LAB attuale ma utile in altri ambienti |
| Scheduler | APScheduler 3.x in un processo dedicato, con lock su PostgreSQL |
| Configurazione | pydantic-settings |
| Auth | Utenti locali (password argon2, cookie di sessione HttpOnly + CSRF token). Entra ID (OIDC) come primo sviluppo dopo l'MVP |
| Frontend | React + TypeScript + Vite, TanStack Query, ECharts (grafici e mappa), client generato da OpenAPI |
| Qualità | ruff, mypy (strict sui collector), pytest + respx |
| CI | GitHub Actions su ogni PR: ruff, mypy, pytest (§14). **Requisito MVP** |
| Backup | `pg_dump` giornaliero su un disco dedicato, separato dal disco di sistema della VM, con prova di ripristino documentata (§15). **Requisito MVP** |
| Deploy | Docker Compose, Caddy come reverse proxy TLS |

## 4. Struttura del repository

```
.
├── .github/workflows/ci.yml        # §14
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── core/                   # config, db, security, classification, logging
│   │   ├── api/v1/                 # router
│   │   ├── models/                 # SQLAlchemy
│   │   ├── schemas/                # Pydantic (I/O API)
│   │   ├── services/               # aggregati, livelli di priorità, feed, topic, matching vittime
│   │   ├── collectors/
│   │   │   ├── base.py             # interfacce PeriodicCollector / ListenerCollector, tipi, SourceLicense
│   │   │   ├── registry.py
│   │   │   ├── http.py             # client condiviso: cache TTL, rate limit, quote, retry
│   │   │   ├── runner.py           # esecuzione periodici
│   │   │   ├── supervisor.py       # esecuzione listener
│   │   │   ├── nvd.py
│   │   │   ├── cisa_kev.py
│   │   │   ├── epss.py
│   │   │   ├── ransomware_live.py
│   │   │   ├── ransomfeed.py
│   │   │   ├── abusech/            # urlhaus.py, threatfox.py, malwarebazaar.py, feodo.py
│   │   │   ├── otx.py
│   │   │   └── csirt_it/           # misp.py, rss.py
│   │   ├── processing/             # post-processor: interfaccia, catena, processori deterministici
│   │   └── scheduler/
│   ├── migrations/
│   └── tests/
│       └── fixtures/<source>/
├── frontend/
├── deploy/
│   ├── docker-compose.yml
│   ├── Caddyfile
│   ├── Dockerfile.*
│   └── backup/                     # script di backup e verifica del ripristino (§15)
├── docs/
│   └── runbook-backup.md           # procedura e registro delle prove di ripristino (§15)
├── .env.example
├── LICENSE
└── CLAUDE.md
```

Gli script bash attuali (`scripts/`, `templates/`, `install.sh`) vengono eliminati (§12).

## 5. Collector a plugin

### 5.1 Metadati comuni

Ogni collector, periodico o listener, dichiara:

```python
class CollectorBase(ABC):
    name: ClassVar[str]                     # "nvd", "abusech.threatfox", "csirt_it.misp", ...
    display_name: ClassVar[str]
    kind: ClassVar[Literal["periodic", "listener"]]
    classification: ClassVar[Classification]  # classe di default dei dati prodotti
    license: ClassVar[SourceLicense]
    rate_limit: ClassVar[RateLimit | None]
    required_settings: ClassVar[tuple[str, ...]] = ()   # mancano → collector disabilitato
    optional_settings: ClassVar[tuple[str, ...]] = ()

    def normalize(self, raw: RawRecord) -> Iterable[Entity]:
        """Pura: record grezzo → entità del modello comune. Nessun I/O."""


@dataclass(frozen=True)
class SourceLicense:
    kind: str                                   # es. "Termini d'uso NVD", "EULA OTX"
    commercial_use: Literal["yes", "no", "to_verify"]
    quota: str | None                           # limite dichiarato, leggibile (es. "500.000 chiamate/mese")
    terms_url: str
    attribution: str | None = None              # testo da mostrare, se richiesto
    notes: str | None = None                    # motivo di "to_verify", vincoli particolari
    verified_on: date | None = None             # ultima verifica dei termini
```

I metadati di licenza sono **codice revisionato**: cambiare `commercial_use` richiede di aggiornare anche la tabella §6.2 di questo documento.

### 5.2 Collector periodici

```python
class PeriodicCollector(CollectorBase):
    kind = "periodic"
    schedule: ClassVar[Schedule]            # Interval(hours=2) | Cron("15 6 * * *")
    cache_ttl: ClassVar[timedelta]

    async def fetch(self, ctx: CollectorContext) -> AsyncIterator[RawRecord]:
        """Scarica dati usando SOLO ctx.http. ctx.cursor = stato dell'ultimo run riuscito."""

    def next_cursor(self, ctx: CollectorContext) -> Cursor | None: ...
```

### 5.3 Collector listener (esecuzione continua)

Per fonti a flusso, dove i dati arrivano come eventi e non si interrogano periodicamente (es. Telegram).

```python
class ListenerCollector(CollectorBase):
    kind = "listener"
    flush_every: ClassVar[timedelta] = timedelta(seconds=30)   # scrittura a lotti
    flush_max_records: ClassVar[int] = 500

    async def listen(self, ctx: ListenerContext) -> AsyncIterator[RawRecord]:
        """Generatore senza fine. Riprende da ctx.checkpoint (es. ultimo message id per canale)."""

    def checkpoint(self, record: RawRecord) -> Checkpoint: ...
```

Il **supervisor** che esegue un listener:
- lo avvia in un proprio processo/container (`python -m app.collectors listen telegram`);
- scrive a lotti (`flush_every` / `flush_max_records`) con la stessa pipeline dei periodici (§5.6);
- salva il checkpoint in `collector_state` dopo ogni lotto scritto, così un riavvio non perde né duplica dati;
- in caso di disconnessione riprova con backoff esponenziale (massimo 5 minuti) e stato `reconnecting`;
- aggiorna un heartbeat ogni 30 secondi: se manca da più di 2 minuti, la vista Fonti mostra lo stato `errore`.

### 5.4 Responsabilità del framework

1. **Abilitazione:** se manca una `required_settings` il collector è `disabled` e non parte; l'app funziona comunque. `COLLECTOR_<NAME>_ENABLED=false` lo disabilita esplicitamente.
2. **Lock:** advisory lock PostgreSQL per collector, quindi nessun run sovrapposto.
3. **Run tracking:** `collector_runs` per i periodici; sessioni e heartbeat in `collector_state` per i listener.
4. **Quote:** il client HTTP conta le richieste per fonte (`source_usage`, per giorno e per mese) e si ferma prima di superare la quota dichiarata, chiudendo il run come `quota_exceeded`.
5. **Upsert idempotente** sulle chiavi naturali; per vittime e IOC si usano entità e avvistamenti (§8.2).
6. **Classificazione:** ogni entità scritta riceve la classe alla raccolta: quella del collector, salvo regole più restrittive (es. TLP, §10.2). Un collector che non dichiara la classe produce dati `sensitive`.
7. **Fallimenti:** un errore su un singolo record viene registrato e il run prosegue; un errore di rete, finiti i tentativi, chiude il run come `failed` senza avanzare il cursore.

### 5.5 Discovery ed esecuzione manuale

- Registrazione con decoratore `@register` in `registry.py`; schedule e TTL sovrascrivibili da ambiente (`COLLECTOR_<NAME>_SCHEDULE`, `COLLECTOR_<NAME>_CACHE_TTL`).
- CLI: `python -m app.collectors run <name> [--full] [--no-cache]` e `python -m app.collectors listen <name>`.
- API admin: `POST /api/v1/admin/collectors/{name}/run` accoda un run, che viene eseguito dallo scheduler.

### 5.6 Pipeline di elaborazione e post-processing

```
fetch / listen ─▶ normalize ─▶ upsert + merge ─▶ post-processing inline ─▶ eventi ─▶ refresh viste
                                                         │
                                                         └─▶ coda post-processing async (roadmap: LLM)
```

Il post-processing è una **catena di processori** con interfaccia comune:

```python
class PostProcessor(ABC):
    name: ClassVar[str]
    version: ClassVar[str]                     # cambiare versione → rielaborazione possibile
    applies_to: ClassVar[frozenset[EntityType]]
    mode: ClassVar[Literal["inline", "async"]]

    async def process(self, entity: EntityRef, ctx: ProcessingContext) -> ProcessingResult: ...
```

- **Inline** (MVP): deterministici e veloci, eseguiti nel run. Esempi: estrazione di CVE ID dal testo degli avvisi CSIRT, normalizzazione nome azienda e dominio delle vittime, mappatura alias di gruppi e famiglie, calcolo del livello di priorità delle CVE. Scrivono in colonne derivate dedicate dell'entità (es. `priority_level`, `name_normalized`, `advisories.cves`), mai nei campi di origine.
- **Async** (roadmap): lenti o costosi, eseguiti dal container `enricher`. È il punto in cui si inserisce l'arricchimento AI (§13.4). Nell'MVP l'interfaccia prevede `mode = "async"` ma non esiste alcun processore async, né le tabelle di coda e di output (`processing_tasks`, `derived_data`), che arriveranno con §13.4.
- Gli eventi del feed si generano dai dati strutturati e non aspettano i processori async.

## 6. Fonti MVP

> Endpoint e limiti verificati sui siti ufficiali il **05/10/2026** dove indicato; per le altre fonti vanno riverificati al momento dell'implementazione. Gli URL base sono configurabili via ambiente.

### 6.1 Accesso e raccolta

| Fonte | Collector | Dati | Accesso | Schedule | TTL cache | Strategia |
|-------|-----------|------|---------|----------|-----------|-----------|
| **NVD** (CVE API 2.0) ✔ verificato | `nvd` | CVE, CVSS (v4.0, v3.x, v2), CWE, CPE e prodotti affetti, riferimenti | `https://services.nvd.nist.gov/rest/json/cves/2.0`. Chiave opzionale `NVD_API_KEY`, inviata nell'header `apiKey`: alza il limite da 5 a 50 richieste ogni 30 s | ogni 2h (NVD chiede di non sincronizzare più spesso) | 1h | Primo caricamento: tutte le pagine con `startIndex` da 0 e `resultsPerPage` predefinito (2.000). Poi incrementale con `lastModStartDate` = ultimo `lastModified` ricevuto e `lastModEndDate` = ora (finestra max 120 giorni). Pausa di 6 s tra le richieste anche con la chiave, come raccomandato da NVD. Le CVE respinte (`Rejected`) restano, con il loro stato. Le metriche SSVC di CISA si ignorano. |
| **CISA KEV** | `cisa_kev` | Catalogo KEV | Pubblico | ogni 6h | 3h | Feed JSON completo, diff con lo stato attuale. |
| **EPSS** (FIRST) ✔ verificato | `epss` | Punteggio, percentile, versione del modello | CSV giornaliero `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (redirect al file del giorno). L'API FIRST è pensata solo per consultazioni puntuali e non si usa per la sincronizzazione | giornaliera, dopo la pubblicazione (~13:30 UTC) | 12h | Punteggio attuale per ogni CVE (~385.000 righe); nello storico solo le variazioni rilevanti (§8.1). Versione del modello e data del punteggio si leggono dalla riga di commento del CSV. |
| **ransomware.live** (API PRO) | `ransomware_live` | Gruppi, vittime (paese, settore, dominio, date) | **Chiave obbligatoria** `RANSOMWARE_LIVE_API_KEY` (`required_settings`), ottenuta da `my.ransomware.live`. Base URL `https://api-pro.ransomware.live`, documentazione `api-pro.ransomware.live/docs`. **L'API v2 gratuita senza chiave non si usa**: è dichiarata solo per uso personale. | ogni 1h | 30m | Vittime recenti e gruppi → entità vittima + avvistamento (§8.2). |
| **Ransomfeed** ✔ verificato | `ransomfeed` | Rivendicazioni ransomware: vittima, gruppo, data, paese, sito web della vittima, settore, città e regione quando presenti, descrizione | API pubblica senza chiave, base URL `https://api.ransomfeed.it` (documentazione `https://ransomfeed.it/docs/`): senza filtri restituisce le ultime 100 rivendicazioni; filtri a percorso (`/country/{paese}`, `/gang/{gruppo}`, `/date/{anno}`, `/search/{testo}`) e numero di righe con `/offset/{n}` (default 100, massimo 1000) | ogni 1h | 30m | Ultime rivendicazioni → entità vittima + avvistamento (§8.2), chiave dell'avvistamento = `id` Ransomfeed. Le rivendicazioni recenti si rileggono a ogni run perché il paese e gli altri campi arrivano con l'analisi successiva (~6 h dopo il rilevamento): l'avvistamento si aggiorna. Primo caricamento: anno corrente con `/date/{anno}`, nei limiti delle 1.000 righe per richiesta; il modo di andare più indietro si verifica in implementazione. Nessun limite di richieste dichiarato: si applica un limite prudenziale di 1 richiesta ogni 10 s. Si usa l'API e non gli RSS, che contengono un sottoinsieme degli stessi dati. |
| **abuse.ch** | `abusech.urlhaus`, `abusech.threatfox`, `abusech.malwarebazaar`, `abusech.feodo` | URL, IOC, metadati e hash dei campioni, C2 | Auth-Key `ABUSECH_AUTH_KEY` | 30m–1h | 15–30m | Export recenti, upsert IOC con avvistamenti per fonte. |
| **AlienVault OTX** | `otx` | Pulse sottoscritti e indicatori | Chiave obbligatoria `OTX_API_KEY` | ogni 1h | 30m | Pulse modificati dopo il cursore. |
| **CSIRT Italia – feed MISP** ✔ verificato | `csirt_it.misp` | Eventi MISP TLP:CLEAR: IOC, famiglie malware, campagne di phishing e smishing, DDoS, sfruttamento di vulnerabilità | Pubblico, `https://www.csirt.gov.it/feed-misp/` (feed MISP standard: `manifest.json`, `hashes.csv`, un JSON per evento) | ogni 1h | 30m | Scarica `manifest.json`, poi solo gli eventi nuovi o con timestamp cambiato; attributi → IOC, tag e galaxy → famiglia e tassonomia, tag TLP → classe (§10.2). |
| **CSIRT Italia – avvisi RSS** ✔ verificato | `csirt_it.rss` | Avvisi e bollettini (titolo, link, data, descrizione) | Pubblico, `https://www.acn.gov.it/portale/feedrss/-/journal/rss/20119/723192` (RSS 2.0, ultimi 50 elementi, nessuna categoria) | ogni 30m | 15m | Dedup su `guid`; estrazione dei CVE ID dal testo (post-processor inline). Finché la licenza non è chiarita (§6.2) si salvano solo titolo, link, data e CVE estratte, non il testo completo. |

Il feed MISP e gli avvisi di CSIRT Italia sono gli unici canali dati strutturati trovati sul portale ACN. Gli altri contenuti (riepilogo operativo mensile, "La Settimana Cibernetica", canali social) sono pubblicazioni editoriali senza feed dedicato e restano fuori dall'MVP.

### 6.2 Licenze, uso commerciale e quote

Questi valori finiscono nei metadati `SourceLicense` di ogni collector e vengono esposti in `GET /sources` e nella vista Fonti.

| Fonte | Licenza / termini | Uso commerciale | Quota dichiarata | Attribuzione | Note |
|-------|-------------------|-----------------|------------------|--------------|------|
| NVD | Pubblico dominio (Title 17 U.S.C.), verificato l'08/10/2026 | **Sì** | 5 richieste / 30 s senza chiave, 50 / 30 s con chiave | **Obbligatoria**: "This product uses data from the NVD API but is not endorsed or certified by the NVD." | Il nome NVD si può usare per indicare la fonte, non per suggerire un'approvazione |
| CISA KEV | **CC0 1.0 Universal** (verificato l'08/10/2026 su cisa.gov) | **Sì** | Nessuna | Non richiesta | Vietato usare logo CISA e sigillo DHS; l'uso dei dati non implica approvazione di CISA/DHS. Feed JSON unico (~1,7 MB); il server invia ETag e Last-Modified ma ha risposto 200 anche a una richiesta condizionale: le richieste ripetute le evita la cache con TTL |
| EPSS | Pubblicazione libera, senza registrazione (FAQ FIRST, verificata l'08/10/2026) | **Sì**, con attribuzione | Nessuna per il CSV giornaliero | Richiesta: "EPSS scores from FIRST.org (https://www.first.org/epss), generated by Empirical Security." | Nessuna licenza formale: la FAQ dichiara l'uso libero e chiede l'attribuzione nei prodotti |
| ransomware.live PRO | Termini e condizioni ransomware.live | **Sì**, dopo aver accettato i T&C | **Da riverificare** sulla pagina ufficiale dell'API PRO e nei T&C: sono emersi valori discordanti (500.000 chiamate/mese e 3.000 chiamate/giorno). Fino alla verifica il collector applica il limite più restrittivo (3.000/giorno) | Da verificare nei T&C | La pagina API indica la PRO (gratuita) per l'uso aziendale. T&C da leggere prima di attivare la chiave |
| Ransomfeed | **CC BY 4.0** ("Ransomfeed © 2026 by Dario Fadda is licensed under CC BY 4.0", footer del sito, verificato il 09/10/2026) | **Sì**, con attribuzione | Nessuna dichiarata | Obbligatoria (CC BY 4.0): "Dati ransomware da Ransomfeed (https://ransomfeed.it), © Dario Fadda, licenza CC BY 4.0." | La pagina dei feed dichiara l'uso "sempre libero e aperto a tutti", anche in piattaforme commerciali. Il connettore OpenCTI di Ransomfeed è GPLv3 ma non si usa: Specula ha un proprio collector |
| abuse.ch | Termini d'uso abuse.ch / Spamhaus | **Da verificare** | Limiti di query per gli utenti non commerciali (non numerici) | Da verificare | I termini prevedono che l'uso da parte di aziende con finalità commerciali o di profitto *possa* richiedere un abbonamento a pagamento gestito da Spamhaus. Va chiarito se l'uso interno difensivo di Eurosystem rientra |
| AlienVault OTX | EULA OTX (LevelBlue) | **Da verificare** | 10.000 richieste/ora con chiave (dato da fonte secondaria, da confermare) | — | L'EULA dichiara OTX gratuito "per uso non commerciale" e vieta la redistribuzione. L'uso interno difensivo sembra compatibile, ma va confermato |
| CSIRT Italia | Feed MISP TLP:CLEAR; note legali del portale ACN | **Da verificare** | Nessuna | ACN / CSIRT Italia | TLP:CLEAR permette la condivisione senza restrizioni, ma le note legali del portale ACN non concedono licenze e vietano riproduzione e uso commerciale senza autorizzazione scritta, salvo uso personale. Proposta: chiedere conferma scritta ad ACN (decisione aperta §11 #10) |

Regola: un collector con uso commerciale **Sì** si attiva normalmente; uno **Da verificare** si attiva solo secondo la regola della decisione aperta §11 #9; uno **No** non si attiva.

## 7. Cache con TTL per fonte

### 7.1 Cache HTTP verso le fonti

Il client condiviso `collectors/http.py` usa la tabella `http_cache` (chiave = hash di metodo, URL, query normalizzata e header rilevanti senza autenticazione; `source`, `fetched_at`, `expires_at`, `etag`, `last_modified`, `status`, `body` compresso).

- Entro il TTL la risposta viene servita dalla cache, senza chiamata di rete e senza consumare quota.
- Dopo il TTL parte una richiesta condizionale (`If-None-Match` / `If-Modified-Since`); con `304` il TTL si rinnova.
- `--no-cache` e i run forzati dagli Admin ignorano la cache.
- Pulizia giornaliera delle voci scadute da più di 7 giorni.
- I listener non usano la cache HTTP: lavorano su flussi.

### 7.2 Aggregati per la dashboard

- KPI e pannelli si leggono da **viste materializzate** aggregate per giorno **e per classe di dati** (es. `mv_kpi_daily(day, classification, …)`). L'API somma solo le classi visibili all'utente, così i conteggi non rivelano dati nascosti.
- Le viste si aggiornano (`REFRESH MATERIALIZED VIEW CONCURRENTLY`) alla fine dei run che toccano i dati relativi.
- Le risposte includono `ETag`, `Cache-Control: private, max-age=60` e il campo `data_as_of`.

## 8. Modello dati

### 8.1 Tabelle principali

Tutte le tabelle di entità, avvistamenti ed eventi hanno la colonna `classification` (`public` | `internal` | `sensitive`), `NOT NULL` con **default `sensitive`**: un dato inserito senza classe esplicita risulta sensibile. È anche il campo su cui si baserà il routing dell'arricchimento AI (§13.4), che nell'MVP non è implementato.

| Tabella | Chiave naturale | Contenuto principale |
|---------|-----------------|----------------------|
| `vulnerabilities` | `cve_id` | descrizione, published/modified, CVSS v3/v4, CWE, stato NVD, `priority_level` (P1–P4) e `priority_reason` calcolati |
| `vulnerability_products` | (cve, vendor, product) | da CPE |
| `kev_entries` | `cve_id` | vendor, product, date_added, due_date, ransomware_use, required_action |
| `epss_scores` | `cve_id` | punteggio **attuale**: epss, percentile, data del punteggio, versione del modello |
| `epss_history` | (cve_id, score_date) | solo **variazioni rilevanti**: prima comparsa, variazione di almeno 0,01, attraversamento della soglia `EPSS_THRESHOLD` o cambio di versione del modello |
| `ransomware_groups` | `slug` | nome, alias, prima e ultima attività |
| `ransomware_victims` | `id` | entità vittima canonica (§8.2) |
| `victim_sightings` | (source, source_record_id) | avvistamenti della vittima per fonte (§8.2) |
| `victim_relations` | (victim_a, victim_b, type) | relazioni tra vittime, es. `shared_domain`, e conferme "distinte" (§8.2) |
| `generic_domains` | `domain` | domini esclusi dalla regola di associazione per dominio (§8.2) |
| `indicators` | (type, value) | first_seen, last_seen, famiglia, tag, confidenza, paese, stato |
| `indicator_sightings` | (indicator, source, source_record_id) | avvistamenti degli IOC per fonte |
| `pulses` | `otx_id` | titolo, autore, tag, TLP, riferimenti, CVE e indicatori collegati |
| `misp_events` | `uuid` | evento MISP di CSIRT Italia: info, data, tag, TLP, timestamp |
| `advisories` | (source, guid) | avvisi CSIRT Italia: titolo, link, data, CVE estratte |
| `events` | `id` | tipo, severità, occurred_at, titolo, entità collegate (JSONB), fonti, chiave di dedup |
| `topics` | `id` | owner, visibilità, criteri, follower |
| `users`, `roles`, `user_grants`, `audit_log` | | autenticazione, ruoli, abilitazioni per classe e fonte, tracciamento |
| `collector_runs`, `collector_state`, `source_usage` | | run, cursori e checkpoint, heartbeat, consumo quote |
| `http_cache` | `key` | §7.1 |
| `aliases` | (kind, alias) | normalizzazione di gruppi e famiglie |

I campi grezzi di ogni fonte restano negli avvistamenti (colonna `raw`, JSONB), così si può rinormalizzare senza riscaricare.

### 8.2 Vittime ransomware: entità e avvistamenti

Le vittime sono gestite come gli IOC: **un'entità canonica** e **più avvistamenti**, uno per ogni fonte e pubblicazione. Nell'MVP le fonti sono ransomware.live e Ransomfeed (§6.1): una vittima pubblicata da entrambe è una sola entità con due avvistamenti. Altre fonti si aggiungeranno allo stesso modo, senza creare duplicati.

**`ransomware_victims` (entità)**

| Campo | Note |
|-------|------|
| `id` | |
| `display_name` | nome mostrato, preso dall'avvistamento più completo |
| `name_normalized` | nome normalizzato per il confronto (vedi sotto) |
| `legal_form` | forma giuridica rimossa dal nome (es. `S.p.A.`, `S.r.l.`, `GmbH`, `Ltd`) |
| `domain` | dominio normalizzato: minuscolo, senza schema, `www.` e path |
| `domain_registrable` | dominio registrabile (eTLD+1) calcolato con la Public Suffix List, es. `mail.acme.it` → `acme.it` |
| `country` | ISO 3166-1 alpha-2 |
| `sector` | settore normalizzato |
| `first_seen`, `last_seen` | dal primo e dall'ultimo avvistamento |
| `external_ids` | JSONB riservato per identificativi futuri (es. partita IVA), usato dal modulo Third-Party Risk |
| `normalization_version` | versione dell'algoritmo di normalizzazione usato |
| `merged_into` | se l'entità è stata unita a un'altra (unione reversibile, tracciata nell'audit log) |
| `classification` | |

**`victim_sightings` (avvistamento)**

`victim_id`, `source`, `source_record_id`, `group_slug`, `name_raw`, `domain_raw`, `country_raw`, `sector_raw`, `published_at`, `discovered_at`, `source_url`, `raw`, `match_rule` (quale regola l'ha associato all'entità), `classification`.

**Normalizzazione del nome** (`normalize_company_name`, versionata): Unicode NFKC, minuscolo, rimozione di accenti e punteggiatura, rimozione delle forme giuridiche da un elenco configurabile (IT: spa, srl, srls, sas, snc, sapa, scarl; estere: ltd, llc, inc, gmbh, ag, sa, sl, bv, nv, …), spazi compattati.

**Regole di associazione** di un nuovo avvistamento, applicate in ordine:
1. Stesso `domain_registrable`, **purché il dominio non sia generico** (vedi sotto) **e i nomi siano compatibili** → stessa vittima. "Compatibili" significa: `name_normalized` uguali, oppure uno contenuto nell'altro, oppure similarità a trigrammi ≥ 0.6 (soglia configurabile).
2. Altrimenti, stesso `name_normalized` **e** (stesso gruppo **oppure** stesso paese) **e** `published_at` entro ±14 giorni → stessa vittima.
3. Altrimenti → nuova vittima.

La similarità approssimata (trigrammi, `pg_trgm`) fuori dalla regola 1 **non unisce in automatico**: produce solo suggerimenti di unione per gli Analyst. I campi `name_normalized`, `domain_registrable` ed `external_ids` sono la base per il futuro confronto con i registri fornitori (modulo Third-Party Risk, fuori MVP).

**Domini generici esclusi dalla regola 1**

Alcuni domini non identificano un'azienda: caselle di posta gratuite, piattaforme di hosting e siti, social network. Due vittime con lo stesso dominio di questo tipo non sono per forza la stessa organizzazione.

- L'elenco è **configurabile** dagli Admin (tabella `generic_domains`, con seed iniziale versionato nel repository) e ogni modifica finisce nell'audit log.
- Seed iniziale di esempio: `gmail.com`, `outlook.com`, `hotmail.com`, `yahoo.com`, `libero.it`, `virgilio.it`, `tiscali.it`, `pec.it`, `aruba.it`, `wixsite.com`, `wordpress.com`, `blogspot.com`, `sites.google.com`, `facebook.com`, `linkedin.com`.
- Le piattaforme che la Public Suffix List tratta già come suffissi (es. `github.io`) producono un `domain_registrable` diverso per ogni sito e non hanno bisogno di stare nell'elenco.
- Per un dominio generico si applicano solo le regole 2 e 3; il dominio resta salvato nell'avvistamento ma non è usato per l'associazione.

**Società diverse con lo stesso dominio**

Succede, ad esempio, con gruppi societari che usano il dominio della capogruppo, filiali in paesi diversi, marchi di un'unica holding, studi associati o consorzi.

- Se due avvistamenti hanno lo stesso `domain_registrable` (non generico) ma **nomi non compatibili**, la regola 1 non si applica: si crea una vittima distinta.
- Le due entità vengono collegate con una relazione `shared_domain` (tabella `victim_relations`, campi: vittima A, vittima B, tipo, origine automatica/manuale). La UI mostra il collegamento ("Stesso dominio di: …") e un suggerimento di unione per gli Analyst.
- Un Analyst può unire le entità (se in realtà sono la stessa organizzazione) oppure confermare che sono distinte; la conferma impedisce che il suggerimento si ripresenti. Entrambe le azioni sono reversibili e registrate nell'audit log.
- La relazione `shared_domain` sarà utile anche al modulo Third-Party Risk, per segnalare quando un fornitore appartiene allo stesso gruppo di una vittima.

## 9. API (sintesi `/api/v1`)

Tutte le letture applicano il filtro per classe e abilitazioni (§10.1).

| Area | Endpoint principali |
|------|---------------------|
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` (ruolo e abilitazioni) |
| Dashboard | `GET /dashboard/kpis?range=7d`, `GET /dashboard/map?layer=…&range=…`, `GET /dashboard/panels/{panel}` |
| Feed | `GET /feed?types=&min_severity=&source=&topic=&q=&cursor=` |
| Vulnerabilità | `GET /cves` (ordinabile per livello di priorità), `GET /cves/{cve_id}` (livello e motivo), `GET /kev` |
| Ransomware | `GET /ransomware/groups`, `GET /ransomware/groups/{slug}`, `GET /ransomware/victims`, `GET /ransomware/victims/{id}` (con avvistamenti) |
| IOC | `GET /iocs`, `GET /iocs/{type}/{value}` (con avvistamenti) |
| Avvisi e MISP | `GET /advisories`, `GET /misp-events/{uuid}` |
| Pulse | `GET /pulses`, `GET /pulses/{id}` |
| Argomenti | `GET /topics/{kind}/{key}/dashboard`, CRUD `/topics`, `POST /topics/{id}/follow` |
| Ricerca | `GET /search?q=` |
| Fonti | `GET /sources` |
| Admin | `POST /admin/collectors/{name}/run`, utenti e abilitazioni, alias, `POST /admin/victims/merge`, `POST /admin/victims/{id}/unmerge` |

**`GET /sources`** restituisce per ogni collector:

```json
{
  "name": "abusech.threatfox",
  "display_name": "abuse.ch – ThreatFox",
  "kind": "periodic",
  "classification": "public",
  "status": "ok",
  "configured": true,
  "last_success_at": "2026-10-05T14:00:12Z",
  "next_run_at": "2026-10-05T14:30:00Z",
  "last_run": { "read": 1240, "inserted": 85, "updated": 310, "errors": 0 },
  "license": {
    "kind": "Termini d'uso abuse.ch / Spamhaus",
    "commercial_use": "to_verify",
    "quota": "Limiti di query per utenti non commerciali",
    "terms_url": "https://abuse.ch/terms-of-use/",
    "attribution": null,
    "notes": "L'uso aziendale a scopo commerciale può richiedere un abbonamento Spamhaus",
    "verified_on": "2026-10-05"
  },
  "usage": { "period": "month", "requests": 1820 }
}
```

`configured` indica solo se la chiave è presente: il suo valore non viene mai restituito.

Convenzioni: errori `application/problem+json`, paginazione a cursore, `range` default `7d`.

## 10. Sicurezza, classificazione e configurazione

### 10.1 Classi di dati e permessi

| Classe | Significato | Accesso |
|--------|-------------|---------|
| `public` | Dati da fonti pubbliche o TLP:CLEAR | Tutti gli utenti autenticati |
| `internal` | Dati del team o di sistemi aziendali | Abilitazione `class:internal`; per le fonti interne serve anche l'abilitazione della fonte (es. `source:tenable`) |
| `sensitive` | Dati che possono contenere informazioni personali o di terzi (es. Telegram, confronto con i fornitori) | Abilitazione esplicita `class:sensitive`; ogni lettura viene registrata nell'audit log |

- **Ruolo e abilitazioni sono indipendenti.** Il ruolo (Viewer / Analyst / Admin) decide le azioni; le abilitazioni (`user_grants`) decidono le classi e le fonti visibili. Anche un Admin vede i dati `sensitive` solo con l'abilitazione esplicita (minimo privilegio). Gli Admin assegnano le abilitazioni e l'operazione è registrata.
- **Applicazione nel backend:** ogni query passa da un livello di repository che aggiunge il filtro sulle classi e sulle fonti consentite. Non esistono query sulle entità che lo saltino; i test coprono ogni endpoint con utenti di abilitazioni diverse.
- **Eventi:** un evento eredita la classe più alta tra le entità collegate.
- **Dati derivati:** ereditano la classe del dato di origine.

### 10.2 Assegnazione della classe

La classe è assegnata **dal collector, al momento della raccolta**, e non viene ricalcolata dopo.

1. Default del collector (`classification`). Se il collector non la dichiara: `sensitive`.
2. Se la fonte fornisce un TLP: `CLEAR` → `public`, `GREEN` → `internal`, `AMBER` / `AMBER+STRICT` → `sensitive`, `RED` → **non viene acquisito**.
3. Una regola può alzare la classe, mai abbassarla.
4. **Un dato senza classe è trattato come `sensitive`** ovunque: default del database, filtri di visibilità e, in futuro, routing dell'arricchimento AI.

### 10.3 Configurazione e segreti

- **`.env`** (mai committato) e **`.env.example`** (committato, senza valori reali):
  ```
  DATABASE_URL=postgresql+asyncpg://...
  SECRET_KEY=
  INTEREST_COUNTRY=IT
  EPSS_THRESHOLD=0.5
  # Fonti
  NVD_API_KEY=                 # opzionale
  RANSOMWARE_LIVE_API_KEY=     # obbligatoria (API PRO)
  ABUSECH_AUTH_KEY=
  OTX_API_KEY=
  MAXMIND_LICENSE_KEY=         # opzionale, GeoLite2 per la mappa
  # Rete LAB
  HTTPS_PROXY=                 # vuoto nel LAB attuale (nessun proxy in uscita)
  ```
- Le chiavi delle fonti arrivano solo al container che esegue il collector (`scheduler`, e in futuro il singolo `listener-*`); il container `api` non le riceve.
- Segreti mascherati nei log.
- Campioni malware **mai scaricati** (solo metadati e hash). Per le vittime ransomware solo metadati pubblici; nessun contenuto trafugato e nessun link ai leak site nella UI.
- Il frontend fa escaping di tutti i contenuti esterni.
- Il database non è esposto fuori dalla rete compose; l'unica porta pubblica è il proxy (443).

## 11. Decisioni

### 11.1 Approvate

| # | Tema | Decisione |
|---|------|-----------|
| 1 | Scheduler | APScheduler in un container dedicato, con lock su PostgreSQL |
| 2 | Cache | Tabella PostgreSQL `http_cache` |
| 3 | Geolocalizzazione IP | Paese indicato dalla fonte quando presente; GeoLite2 (MaxMind) opzionale con `MAXMIND_LICENSE_KEY` |
| 4 | Ordinamento CVE | Livelli P1–P4 (specifica §6) al posto del punteggio pesato |
| 5 | Retention | Eventi e IOC 12 mesi, storico EPSS (solo variazioni rilevanti, §8.1) 6 mesi, CVE e KEV senza scadenza |
| 6 | Autenticazione | Utenti locali nell'MVP; Entra ID (OIDC) come primo sviluppo successivo |
| 7 | Script legacy | Eliminati dopo aver creato il tag `legacy-final` (§12) |
| 8 | Arricchimento AI | Approccio ibrido (§13.4): interfaccia comune con provider intercambiabili; provider remoto solo per dati `public`, provider locale su CPU per `internal` e `sensitive`; audit di ogni chiamata remota. Fuori MVP: nell'MVP esiste solo il campo `classification` |
| 12 | TLS e rete nel LAB | **Certificato autofirmato** generato sulla VM dalla CA locale di Caddy (`tls internal`), valido per l'indirizzo 10.128.4.106. Per evitare l'avviso del browser, il certificato radice della CA di Caddy va installato sui PC degli analisti. Nessun proxy in uscita |
| 14 | Destinazione dei backup | Cartella dedicata `specula-backup` (root, `700`) sul **disco dati da 3,6 TB** della macchina, fisicamente separato dal disco di sistema, resa disponibile in `/mnt/specula-backup` con un bind mount (§15.1) |
| 15 | Ransomfeed | Anticipato nell'MVP, in M6 dopo ransomware.live, come seconda fonte di avvistamenti delle vittime (§6.1) |
| 16 | Arricchimento on-demand (VirusTotal, Shodan) | Dopo il rilascio dell'MVP, con il meccanismo di §13.5 |
| 17 | Monitor dei leak (IntelX, Dexpose) | Nel futuro modulo **Exposure**, non in Specula Threat (§13.6) |

### 11.2 Aperte

| # | Tema | Proposta |
|---|------|----------|
| 9 | Fonti con uso commerciale "Da verificare" (abuse.ch, OTX, CSIRT Italia) | Attive solo nel LAB, in fase di valutazione; prima di qualunque uso in produzione la verifica va chiusa e la tabella §6.2 aggiornata |
| 10 | CSIRT Italia | Chiedere ad ACN conferma scritta sul riuso del feed MISP e degli avvisi RSS in una piattaforma interna; fino ad allora, per gli avvisi solo titolo, link, data e CVE estratte |
| 11 | Associazione delle vittime | Finestra di ±14 giorni ed elenco delle forme giuridiche come in §8.2 |
| 13 | Provider AI (roadmap) | Scelta del provider remoto e del modello locale per CPU, da fare prima di avviare §13.4 |
| 18 | Piano VirusTotal | Il piano Public in uso non è compatibile con l'uso in Eurosystem (§13.5). Proposta: valutare il piano Premium prima di avviare §13.5; fino ad allora VirusTotal non si integra |
| 19 | Piano Shodan | Con la membership Academic: 100 crediti di query al mese e uso commerciale non indicato nella pagina dell'offerta. Proposta: verificare i termini con Shodan (o passare a un piano a pagamento) prima di avviare §13.5 |

## 12. Riutilizzo del codice esistente e rimozione degli script legacy

Il repository contiene oggi script bash di **ricognizione attiva** su un dominio e un generatore di report HTML. Nessuna delle fonti MVP è coperta.

- **Codice riutilizzabile direttamente:** nessuno. Gli script sono shell, legati al filesystem locale e hanno bug che ne compromettono l'output.
- **Concetti riutilizzati:** "un modulo per tool" → interfaccia dei collector; report di dominio → dashboard di argomento; "plugin system" del README → registro dei collector.
- **Da tenere:** licenza MIT (dichiarata nel README; va aggiunto il file `LICENSE`), nome del repository e autore. Il README va riscritto.

**Rimozione (decisione §11 #7)**, come primo passo dell'implementazione:
1. Creare sul commit attuale di `main` il tag annotato `legacy-final` e pubblicarlo su GitHub.
2. Su un branch dedicato eliminare `scripts/`, `templates/` e `install.sh`, e riscrivere il README indicando il tag per chi cerca i vecchi script.
3. Merge tramite PR.

## 13. Roadmap fonti (fuori MVP)

Le fonti della roadmap usano gli stessi meccanismi già presenti nell'MVP: listener (§5.3), classi di dati (§10), avvistamenti delle vittime (§8.2) e post-processing (§5.6). Per ognuna, prima dell'implementazione servono una specifica dedicata e la verifica di termini e licenza.

### 13.1 Tenable.ONE

- **Collector periodico** `tenable_one`, via API in **sola lettura**.
- Chiavi di un **utente di servizio dedicato** con ruolo di sola lettura su Tenable (`TENABLE_ACCESS_KEY`, `TENABLE_SECRET_KEY`), fornite solo al container che esegue il collector.
- Dati: asset (hostname, IP, sistema operativo, tag) e vulnerabilità rilevate (CVE, asset, gravità, stato, prima e ultima rilevazione). Si acquisisce solo ciò che serve alla correlazione.
- Classe `internal` con abilitazione di fonte `source:tenable`: la vista "Esposizione interna" è visibile solo a chi la possiede.
- Correlazione con KEV, EPSS e livelli P1–P4: quali asset aziendali sono esposti alle CVE prioritarie.
- Endpoint e prodotto esatto (Tenable.ONE Exposure Management o Tenable Vulnerability Management) da verificare sulla documentazione ufficiale.

### 13.2 Ransomfeed

Anticipato nell'MVP (decisione §11.1 #15): collector `ransomfeed` in §6.1 e §6.2, milestone M6.

### 13.3 Telegram

- **Collector listener** `telegram`, con un **account dedicato** alla piattaforma (mai un account personale) e client MTProto.
- **Solo testo e metadati** (canale, id messaggio, data, autore se pubblico, inoltri, link, tipo di eventuale media). **Nessun download di media**: il codice non chiama le funzioni di download e un test lo verifica; dei media si registra solo il tipo.
- Canali seguiti scelti dagli Admin, con elenco versionato e tracciato nell'audit log.
- **Container isolato** `listener-telegram`:
  - rete dedicata, con uscita consentita solo verso Telegram;
  - riceve solo i propri segreti (sessione dell'account, `TELEGRAM_*`) e nessun'altra chiave;
  - utente database con permessi minimi (scrittura solo sulle proprie tabelle di staging, nessuna lettura delle altre);
  - filesystem in sola lettura tranne la sessione.
- Classe `sensitive`, retention breve (da definire, proposta 90 giorni).
- I messaggi arrivano nel feed solo come eventi collegati a entità note (CVE, gruppi, vittime), estratte dal post-processing.
- **Messaggi con possibili dati trafugati o personali.** Un post-processor inline e deterministico (§5.6), eseguito **prima** dell'indicizzazione, segnala i messaggi che sembrano contenere:
  - credenziali (es. coppie email/utente e password, "combolist", token e chiavi);
  - elenchi di dati personali o aziendali (molte righe con struttura ripetuta, elenchi di email, numeri di telefono, codici fiscali, IBAN);
  - annunci di vendita o pubblicazione di dump e database.

  Per i messaggi segnalati:
  - il flag (`content_flags`, con il motivo) viene salvato sul messaggio;
  - il testo **non entra nell'indice full-text**: il messaggio non è trovabile con la ricerca testuale, ma resta raggiungibile dalle entità collegate (canale, gruppo, vittima);
  - alla scadenza della retention il messaggio viene **cancellato definitivamente** (testo, metadati e dati derivati), come gli altri messaggi Telegram. Nessuna proroga, nemmeno per i messaggi segnalati.

  Il rilevamento è a regole (pattern ed euristiche versionati e testati). In futuro potrà essere affiancato dal provider AI locale, mai da quello remoto, perché i dati sono `sensitive`.
- La cancellazione alla scadenza è un job giornaliero dello scheduler. I backup (§15) hanno una retention limitata, quindi i dati cancellati spariscono anche dai backup entro quel periodo.
- Prima dell'attivazione: valutazione privacy (GDPR) e verifica dei termini di Telegram.

### 13.4 Arricchimento AI (approccio ibrido)

Decisione approvata §11 #8. **Fuori MVP**: nell'MVP esiste solo la colonna `classification` (§8.1, §10.2), su cui si baserà il routing.

**Compiti** (post-processor async, §5.6, eseguiti dal container `enricher`):
- **traduzione** in italiano di avvisi, pulse e messaggi;
- **sintesi** di testi lunghi;
- **estrazione di entità** (CVE, IOC, gruppi, famiglie, paesi, settori, organizzazioni).

**Interfaccia comune, provider intercambiabili**

```python
class AIProvider(ABC):
    name: ClassVar[str]                          # es. "local-cpu", "remote-<vendor>"
    location: ClassVar[Literal["local", "remote"]]
    allowed_classes: ClassVar[frozenset[Classification]]

    async def complete(self, task: AITask, content: str, schema: type[BaseModel]) -> AIResult: ...
```

- I compiti non conoscono il provider: chiedono un'esecuzione e il **router** sceglie il provider in base alla classe del dato.
- Provider **locale su CPU**, nel container `llm` sulla VM del LAB, che non ha GPU: `allowed_classes = {public, internal, sensitive}`. Su CPU servono un modello piccolo e quantizzato e un'elaborazione in coda con priorità; i tempi di risposta non sono interattivi.
- Provider **remoto via API**: `allowed_classes = {public}`, senza eccezioni.

**Regole di routing** (applicate dal router, non dai singoli compiti):

| Classe del dato | Provider ammessi |
|-----------------|------------------|
| `public` | remoto (preferito per qualità e velocità) oppure locale |
| `internal` | **solo locale** |
| `sensitive` | **solo locale** |
| assente / non valida | trattata come `sensitive` → **solo locale** |

- Se un input contiene più entità, vale la **classe più alta**.
- Il router verifica la classe immediatamente prima dell'invio: se il provider non è ammesso, la chiamata viene rifiutata (errore, non fallback silenzioso), salvo l'uso del provider locale.
- Se il provider remoto non è disponibile, i dati `public` possono passare al locale; il contrario non è mai possibile.

**Audit delle chiamate remote**

Ogni chiamata a un provider remoto genera una riga nell'audit log con: provider, data e ora, tipo di contenuto (es. `advisory.text`, `pulse.description`), compito, classe verificata, riferimento all'entità e dimensione dell'input. Il testo inviato non viene copiato nell'audit log: resta recuperabile dall'entità di origine. Le chiamate al provider locale si tracciano solo nei log applicativi.

**Output**

- Vincolato a uno schema JSON e validato con Pydantic. IOC e CVE estratti vengono riconvalidati con parser deterministici prima di essere collegati.
- Salvato nella tabella `derived_data` (introdotta con questa fase) con provider, modello, versione del modello e versione del prompt. I dati di origine non cambiano.
- I dati derivati ereditano la classe di origine.
- Sempre etichettato "generato da AI" nella UI. Le entità estratte sono collegamenti suggeriti e **non generano da sole eventi di severità Alta o Critica**.
- Configurazione prevista: `AI_REMOTE_PROVIDER`, `AI_REMOTE_API_KEY` (solo nel container `enricher`), `AI_LOCAL_URL`, `AI_LOCAL_MODEL`.
- È la base tecnica del futuro **briefing AI** (fuori MVP).

### 13.5 Arricchimento on-demand: VirusTotal e Shodan

Dopo il rilascio dell'MVP (decisione §11.1 #16). Serve una specifica dedicata; qui si fissano i vincoli.

**Cosa fa.** Dal dettaglio di un IOC un Analyst preme "Arricchisci" e ottiene il quadro della fonte esterna:
- **VirusTotal**: report esistenti di hash, IP, domini e URL (rilevamenti, prima e ultima analisi, reputazione);
- **Shodan**: dati dell'host per un IP (porte, servizi, banner sintetici, CVE dichiarate da Shodan, organizzazione, ASN).

**Flusso.** La regola "l'API non chiama mai fonti esterne" resta valida e le chiavi restano solo nello scheduler:
1. l'API riceve `POST /api/v1/enrichments` (ruolo Analyst o superiore) e registra una riga in `enrichment_requests` (stato `queued`);
2. un job dello scheduler preleva le richieste in coda e le esegue con il client HTTP condiviso (cache con TTL, rate limit, quote, retry);
3. il risultato va in `enrichment_results` (campi di sintesi più `raw` JSONB) e la richiesta passa a `done` o `failed`;
4. la UI interroga `GET /api/v1/enrichments/{id}` finché il risultato non è pronto.

**Regole**
- **Solo consultazione.** Nessun caricamento di file o URL per l'analisi: il codice non chiama gli endpoint di upload o di scansione e un test lo verifica. Il connettore OpenCTI lo faceva (`VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS`, `VIRUSTOTAL_URL_UPLOAD_UNSEEN`): per Specula significherebbe divulgare dati.
- **Cosa si può inviare.** Il valore inviato a un servizio esterno ne rivela l'interesse. Si inviano solo IOC di classe `public`; gli indirizzi privati (RFC 1918, loopback, link-local) e i domini dell'organizzazione configurati dagli Admin sono rifiutati.
- **Classe del risultato: `internal`.** Le ricerche del team dicono cosa sta indagando, anche quando il dato di partenza è pubblico.
- **Audit.** Ogni richiesta registra utente, fornitore, tipo e valore dell'indicatore.
- **Quote.** Limite giornaliero per fornitore (dalla `Quota` del collector) e per utente (configurabile). Un risultato in cache entro il TTL (proposta 24 h) non consuma quota.
- Chiavi `VIRUSTOTAL_API_KEY` e `SHODAN_API_KEY`, solo nello scheduler.

**Piani disponibili e condizioni (verificate il 09/10/2026)**
- **VirusTotal Public**: 500 richieste al giorno e 4 al minuto. La documentazione ufficiale (*Public vs Premium API*) stabilisce che non va usata in prodotti o servizi commerciali, né in flussi di lavoro aziendali che non contribuiscono nuovi file. L'uso di Specula in Eurosystem, a nostra lettura, rientra almeno nel secondo caso: **con il piano Public l'integrazione non si fa** (decisione aperta §11.2 #18).
- **Shodan Academic**: 100 crediti di query e 100 di scansione al mese, monitoraggio di 16 IP; il filtro `vuln` funziona solo sul sito web, non via API. La pagina dell'offerta non parla di uso commerciale: va verificato con Shodan (decisione aperta §11.2 #19). Il consumo di crediti per ciascun endpoint si verifica in implementazione.

### 13.6 Monitor dei leak: IntelX e Dexpose (modulo Exposure)

Fuori da Specula Threat: appartiene al futuro modulo **Exposure** (decisione §11.1 #17), che avrà una specifica propria. I principi seguenti valgono già, perché queste fonti restituiscono credenziali in chiaro.

**Cosa fa.** Per una lista di domini monitorati, gestita dagli Admin e tracciata nell'audit log, mostra quanto l'organizzazione è esposta: dipendenti e utenti compromessi, log di infostealer, breach pubblici, menzioni, con date e andamento.

**Cosa si salva e cosa no**
- **Si salvano** conteggi e metadati: dominio, tipo (infostealer, combo, ULP, breach pubblico), famiglia dello stealer, data di compromissione e di pubblicazione, paese dell'host, nome del breach.
- **Indirizzi email**: mai in chiaro. Si salvano un'impronta HMAC con chiave segreta (per riconoscere la stessa persona tra fonti e nel tempo) e una forma mascherata (es. `m***@dominio.it`).
- **Mai**: password, hash delle password, cookie, token, alberi dei file delle macchine infette, contenuti di messaggi o post. Il collector li scarta prima di qualunque scrittura o log; un test verifica che nessuno di questi campi arrivi al database.
- Classe `sensitive`, abilitazione di fonte (`source:dexpose`, `source:intelx`), audit di ogni lettura.
- Prima dell'attivazione: valutazione privacy (GDPR), perché sono dati personali di dipendenti e utenti.

**Dexpose** (DeXpose Search API, specifica OpenAPI letta il 09/10/2026)
- Header `X-Dexpose-Token`; addebito a crediti per risultato; al massimo 5.000 risultati per ricerca (25 per pagina). La chiave ha scadenza, rotte e IP consentiti e un'opzione `censor_passwords`, da attivare sulla chiave aziendale.
- Endpoint utili per il monitor: `POST /api/v1/domain_statistics` (statistiche aggregate per dominio, il più adatto a una raccolta periodica) e `GET /api/v1/api_key_details` (crediti residui, per la `Quota`). Le ricerche puntuali (`search_infostealer_data`, `all_credz_search`, `public_breaches_search`) restituiscono anche password: si usano solo per i conteggi, con lo scarto descritto sopra. `machine_info` (file delle macchine infette) non si usa.
- Le ricerche su Telegram e forum (`search_telegram_messages`, `search_web_data`) sono da valutare come alternativa o complemento del listener Telegram (§13.3), con le stesse regole sui contenuti.

**IntelX** (piano aziendale): endpoint, crediti e condizioni da verificare sulla documentazione ufficiale al momento della specifica.

Per entrambi i fornitori le condizioni d'uso sono nel contratto aziendale: vanno riportate in `SourceLicense` e in §6.2 prima dell'attivazione.

### 13.7 Altre fonti candidate

Emerse dalla configurazione OpenCTI esistente del team. Ognuna richiede verifica di termini e limiti e una specifica prima dell'implementazione.

| Fonte | Cosa porterebbe |
|-------|-----------------|
| **MITRE ATT&CK** | Tecniche, gruppi, malware e strumenti: contesto per gruppi ransomware e famiglie malware |
| **abuse.ch SSLBL** | Certificati e IP dei C2 con TLS; sotto-fonte aggiuntiva della famiglia abuse.ch (§6.1) |
| **AbuseIPDB** (blacklist) | IP segnalati con punteggio di confidenza; richiede una chiave |
| **URLScan** (phishfeed) | URL di phishing recenti; richiede l'API PRO |
| **Dataset OpenCTI** (settori, geografia) | Tassonomia dei settori e dei paesi per normalizzare le vittime |

## 14. Integrazione continua (CI) – requisito MVP

Pipeline **GitHub Actions** in `.github/workflows/ci.yml`, eseguita su **ogni pull request** verso `main` e su ogni push su `main`. Una PR si può unire solo se tutti i controlli sono verdi.

| Job | Contenuto | Da quando |
|-----|-----------|-----------|
| `backend-lint` | `ruff check` e `ruff format --check` | M1 |
| `backend-types` | `mypy` sul backend, `--strict` su `app/collectors/` | M1 |
| `backend-test` | `pytest` con un servizio `postgres:16`: prima `alembic upgrade head`, poi i test. Report di copertura come artefatto | M1 |
| `images` | Build delle immagini Docker (senza pubblicarle), per intercettare errori nei Dockerfile | M1 |
| `frontend` | `npm ci`, lint, controllo dei tipi, test, build | M5 |

Regole:
- Python 3.12 fissato; dipendenze installate da un **lockfile** (proposta: `uv`), con cache tra le esecuzioni.
- La CI **non usa chiavi API reali** e i test non chiamano le fonti esterne (fixture e `respx`). Un test che tenta una connessione di rete non simulata fallisce.
- Su `main` va attivata la **branch protection**: PR obbligatoria e controlli CI richiesti. È un'impostazione del repository GitHub, da attivare dal proprietario.
- La CI non fa deploy: il rilascio sulla VM del LAB resta manuale nell'MVP.

## 15. Backup e ripristino – requisito MVP

### 15.1 Backup giornaliero

- **Container `backup`** nel compose (`deploy/backup/`), basato sull'immagine di PostgreSQL 16 con `age`; lo script `backup.sh` attende l'orario giornaliero e lancia il dump.
- Ogni notte (default 02:30, fuso `Europe/Rome`) esegue `pg_dump --format=custom` del database e produce `specula-AAAAMMGG-hhmm.dump.age` più un file `.sha256` di controllo.
- Il dump viene **cifrato con `age`** mentre viene prodotto, con la chiave pubblica `BACKUP_AGE_RECIPIENT`: non esiste mai una copia in chiaro. La chiave privata **non è salvata sull'host**: è custodita dal responsabile della piattaforma ed è necessaria per il ripristino. La coppia di chiavi è stata generata in un container temporaneo sull'host, che l'ha trasmessa via SSH al PC del responsabile senza scriverla su disco: la chiave privata è passata solo per la memoria dell'host (deroga accettata, sul PC non è disponibile `age`).
- **Protezione dal disco non montato:** il job scrive solo se nella cartella esiste il file marcatore `.specula-backup-disk`, creato una volta sul disco dati. Se il disco non è montato, `/mnt/specula-backup` è una cartella vuota sul disco di sistema, senza marcatore, e il job si rifiuta di scrivere.
- **Destinazione:** la cartella `specula-backup` sul disco dati della macchina (`/dev/sda1`, 3,6 TB, fisicamente separato dal disco di sistema), di proprietà di root con permessi `700`. È resa disponibile in **`/mnt/specula-backup`** con un bind mount in `/etc/fstab` (opzioni `nofail` e `x-systemd.requires-mounts-for`), così il percorso usato dal container non dipende da dove è montato il disco (decisione §11 #14). Il container `backup` scrive solo lì. Un backup sul disco di sistema non soddisfa il requisito.
- **Rischi residui** (accettati per l'MVP nel LAB):
  - il disco dati protegge da guasti o corruzione del disco di sistema e del database, ma **non** da perdita, furto, incendio o compromissione della **macchina fisica**, su cui risiedono entrambi i dischi;
  - il disco dati ospita anche la condivisione Samba di un altro utente, la cui cartella principale è scrivibile da `nobody`. Chi accede alla condivisione **non può leggere né svuotare** `specula-backup` (root, `700`; i dump sono comunque cifrati), ma **potrebbe rinominarla o spostarla**. Il monitoraggio (sotto) segnala come errore la mancanza del backup recente;
  - con `nofail`, se il disco dati non è disponibile all'avvio la macchina parte comunque: il job di backup fallisce, senza scrivere sul disco di sistema, grazie al file marcatore.

  Prima di un uso in produzione va prevista una copia periodica fuori dalla macchina (es. storage di backup del LAB).
- **Retention:** 7 backup giornalieri + 4 settimanali (domenica), circa 30 giorni. I file più vecchi vengono eliminati dal job stesso. Questo limite garantisce anche che i dati cancellati per retention (es. Telegram, §13.3) spariscano dai backup entro 30 giorni.
- **Obiettivi:** RPO 24 ore (si perde al massimo un giorno di dati, che i collector possono in gran parte riscaricare); RTO 2 ore.
- **Monitoraggio:** il job registra esito, ora, file, dimensione e durata in `last-backup.json` nella cartella dei backup e nei log JSON del container. Da M4 gli Admin li vedono nella vista Fonti, nella sezione "Stato sistema" (`GET /api/v1/admin/system`), dove un backup fallito o più vecchio di 26 ore viene mostrato come errore.

### 15.2 Prova di ripristino documentata

La procedura è scritta in `docs/runbook-backup.md` e prevede:

1. Scelta del dump (l'ultimo, oppure uno indicato) e verifica del checksum.
2. Decifratura con la chiave privata, passata al container tramite lo standard input e mai scritta su disco.
3. Ripristino con `pg_restore` in un PostgreSQL **temporaneo** avviato in memoria dentro un container usa-e-getta (`deploy/backup/verify-restore.sh`), mai sul database in uso.
4. Verifica: versione delle migrazioni (`alembic_version`) uguale a quella del database in uso, presenza di tutte le tabelle e confronto del numero di righe per tabella. Da M2, quando ci saranno dati, si aggiungono query di controllo (es. una CVE e una voce KEV note).
5. Eliminazione del container temporaneo.
6. **Registrazione** della prova nel registro in fondo al runbook: data, dump usato, durata, esito ed eventuali problemi.

Lo stesso flusso (rifiuto senza marcatore, dump cifrato, ripristino con la chiave giusta, fallimento con una chiave sbagliata) è verificato a ogni PR dal job CI `images`.

**Quando si fa:** al primo avvio sulla VM (criterio di completamento della milestone che introduce il backup), poi **una volta al mese** e dopo ogni aggiornamento di versione di PostgreSQL.
