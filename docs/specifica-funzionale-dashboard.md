# Specula Threat – Specifica funzionale della dashboard

> Stato: **APPROVATO – v1.4** (09/10/2026)
> Prodotto: **Specula Threat**, modulo di Threat Intelligence della piattaforma **Specula** (moduli futuri: Exposure, Third Party, OSINT, CLOSINT).
> Ambito: MVP. Fonti dati: NVD, CISA KEV, EPSS, ransomware.live (API PRO), Ransomfeed, abuse.ch, AlienVault OTX, CSIRT Italia.
> Documenti collegati: [architettura.md](architettura.md) · [identita-visiva.md](identita-visiva.md)
>
> Versioni: v1.0 approvazione iniziale · v1.1 modifica editoriale (nome del prodotto), nessuna modifica funzionale · v1.2 destinazione dei backup allineata alla decisione #14 dell'architettura · v1.3 Ransomfeed tra le fonti MVP; roadmap: arricchimento on-demand (VirusTotal, Shodan) dopo il rilascio, monitor dei leak (IntelX, Dexpose) nel modulo Exposure · v1.4 regole di accesso degli utenti locali, con TOTP per gli Admin (§2).

---

## 1. Obiettivo

Offrire a un team di analisti una vista unica e sempre aggiornata sul panorama delle minacce, che risponda a tre domande:

1. **Cosa sta succedendo adesso?** (dashboard globale e intel feed)
2. **Cosa devo prioritizzare?** (vulnerabilità sfruttate o ad alta probabilità di sfruttamento)
3. **Cosa riguarda il mio perimetro?** (dashboard di argomento: vendor, paese, settore, gruppo, famiglia malware)

Specula Threat non esegue scansioni attive: aggrega, normalizza e correla dati da fonti pubbliche o autenticate.

## 2. Utenti e ruoli

| Ruolo | Può fare |
|-------|----------|
| **Viewer** | Consulta dashboard, feed, dettagli; esporta viste. |
| **Analyst** | Tutto ciò che fa il Viewer, in più crea, modifica e condivide argomenti (topic) e watchlist. |
| **Admin** | Tutto ciò che fa l'Analyst, in più gestisce utenti, vede lo stato delle fonti, forza un aggiornamento manuale, abilita o disabilita i collector. Non vede mai il valore delle chiavi API, solo se sono presenti. |

Ogni azione di modifica (topic, utenti, run manuali) finisce nell'audit log.

**Accesso.** Nell'MVP gli utenti sono locali ed entrano con email e password (almeno 14 caratteri; le password comuni o già trapelate vengono rifiutate). Gli **Admin** confermano l'accesso anche con un codice da app di autenticazione (TOTP). La sessione dura al massimo 10 ore e scade dopo 60 minuti di inattività. Dopo 5 tentativi falliti l'account si blocca per 15 minuti. Senza login non si vede nessun dato. Con Entra ID (dopo l'MVP) l'accesso passerà all'account aziendale.

### 2.1 Classificazione dei dati

Ogni dato ha una classe, e un utente vede solo le classi per cui è abilitato. Il ruolo stabilisce cosa l'utente può *fare*; le abilitazioni stabiliscono cosa può *vedere*.

| Classe | Esempi | Chi la vede |
|--------|--------|-------------|
| **Pubblico** | NVD, KEV, EPSS, IOC abuse.ch, pulse OTX pubblici, CSIRT Italia (TLP:CLEAR), vittime ransomware | Tutti gli utenti |
| **Interno** | Topic e note del team; in futuro asset e vulnerabilità interne (Tenable.ONE) | Utenti con abilitazione *Interno*. Le viste legate a una singola fonte interna richiedono anche l'abilitazione specifica, es. Tenable |
| **Sensibile** | In futuro: messaggi Telegram, confronto vittime ↔ registro fornitori | Solo utenti con abilitazione *Sensibile* esplicita, assegnata da un Admin; ogni accesso è registrato nell'audit log |

Regole visibili all'utente:
- Gli elementi non pubblici hanno un badge di classe (Interno / Sensibile).
- KPI, mappa e conteggi includono solo i dati delle classi visibili all'utente: un numero non deve mai rivelare l'esistenza di dati che l'utente non può vedere.
- Un evento del feed eredita la classe più alta tra le entità collegate.
- La classe viene assegnata alla raccolta, dalla fonte che produce il dato. **Un dato senza classe è trattato come Sensibile.**
- L'accesso ai dati Sensibili richiede l'abilitazione esplicita anche per gli Admin.

Nell'MVP tutte le fonti sono di classe Pubblico; il meccanismo delle classi esiste già per accogliere le fonti della roadmap (§10).

## 3. Elementi comuni a tutte le viste

- **Selettore di periodo**: 24h · 7g (default) · 30g · 90g · personalizzato. Tutti i KPI, i pannelli e la mappa lo rispettano.
- **Indicatore di freschezza**: per ogni fonte mostra l'ora dell'ultimo aggiornamento riuscito e lo stato (OK / in ritardo / errore / disabilitata per chiave mancante). Se una fonte è in ritardo, i widget che la usano lo segnalano con un badge.
- **Ricerca globale**: accetta un CVE ID, un IOC (IP, dominio, URL, hash), il nome di un gruppo ransomware, una famiglia malware o un vendor, e porta al dettaglio o alla dashboard di argomento corrispondente.
- **Click-through**: ogni numero, barra o paese è cliccabile e apre l'elenco filtrato dei dati da cui deriva. Nessun numero "orfano".
- **Esportazione**: CSV per gli elenchi, PNG per i grafici. Il PDF è fuori MVP.
- **Paese di interesse**: configurabile a livello di istanza (default `IT`), evidenziato su mappa e KPI dedicati.

## 4. Dashboard globale

### 4.1 Layout

```
┌──────────────────────────────────────────────────────────────────────┐
│ Periodo [7g ▾]   Ricerca globale ……………………     Fonti: ● ● ● ● ● ●     │
├────────┬────────┬────────┬────────┬────────┬────────┬────────┬───────┤
│ KPI 1  │ KPI 2  │ KPI 3  │ KPI 4  │ KPI 5  │ KPI 6  │ KPI 7  │ KPI 8 │
├────────┴────────┴────────┴────────┴──────────┬───────────────────────┤
│                                              │                       │
│                 MAPPA MONDO                  │      INTEL FEED       │
│                                              │   (stream unificato)  │
├──────────────────────┬───────────────────────┤                       │
│  CVE prioritarie     │  Ultime KEV           │                       │
├──────────────────────┼───────────────────────┤                       │
│  Top gruppi ransom.  │  Settori colpiti      │                       │
├──────────────────────┼───────────────────────┤                       │
│  Famiglie malware    │  IOC per tipo / fonte │                       │
├──────────────────────┴───────────────────────┴───────────────────────┤
│  Top vendor/prodotti          │  Bollettini CSIRT Italia             │
├───────────────────────────────┴──────────────────────────────────────┤
│  Pulse OTX recenti                                                   │
└──────────────────────────────────────────────────────────────────────┘
```

Su schermi stretti l'ordine diventa: KPI → feed → mappa → pannelli.

### 4.2 KPI

Ogni tile mostra: **valore**, **variazione** rispetto al periodo precedente di pari durata (assoluta e %), **sparkline** giornaliera e la **fonte**.

| # | KPI | Definizione | Fonte |
|---|-----|-------------|-------|
| 1 | **Nuove CVE** | CVE con `published` nel periodo | NVD |
| 2 | **CVE critiche** | Nuove CVE con CVSS base ≥ 9.0 (si usa v4.0 se presente, altrimenti v3.x) | NVD |
| 3 | **Nuove KEV** | Voci con `dateAdded` nel periodo | CISA KEV |
| 4 | **KEV legate a ransomware** | Nuove KEV con `knownRansomwareCampaignUse = Known` | CISA KEV |
| 5 | **CVE ad alto rischio EPSS** | CVE il cui punteggio EPSS ha superato la soglia nel periodo (soglia default 0.5, configurabile) | EPSS |
| 6 | **Vittime ransomware** | Vittime pubblicate nel periodo (una vittima segnalata da più fonti conta una volta); sotto-valore: di cui nel paese di interesse | ransomware.live, Ransomfeed |
| 7 | **Gruppi ransomware attivi** | Gruppi con almeno una vittima nel periodo | ransomware.live, Ransomfeed |
| 8 | **Nuovi IOC** | IOC distinti con `first_seen` nel periodo; sotto-valore: C2 attivi (Feodo Tracker, ThreatFox `botnet_cc`) | abuse.ch, OTX, CSIRT Italia (MISP) |

Cliccando su un KPI si apre l'elenco filtrato, ad esempio KPI 3 → tabella KEV del periodo.

### 4.3 Mappa

- **Choropleth mondiale** con due livelli alternativi (toggle):
  - **Vittime ransomware per paese** (default): conteggio vittime nel periodo, dal campo paese delle fonti ransomware (ransomware.live, Ransomfeed).
  - **Infrastruttura malevola per paese**: IOC di tipo IP geolocalizzati. Usa il paese fornito dalla fonte (es. Feodo Tracker) o, se assente e se configurato, il database GeoIP locale GeoLite2 (architettura §11, decisione #3).
- Scala colori sequenziale e legenda con i valori; i paesi senza dati sono distinti da quelli con zero.
- **Hover**: nome paese, conteggio, variazione vs periodo precedente.
- **Click su un paese**: pannello laterale con top gruppi, top settori, ultime 10 vittime, IOC principali e pulsante **"Apri dashboard Paese"**.
- Il paese di interesse ha un contorno evidenziato.

### 4.4 Pannelli

| Pannello | Contenuto | Interazione |
|----------|-----------|-------------|
| **CVE prioritarie** | Top 10 CVE del periodo ordinate per *livello di priorità* (§6). Colonne: livello, CVE, vendor/prodotto, CVSS, EPSS (percentile), in KEV sì/no, ransomware sì/no. | Click → dettaglio CVE |
| **Ultime KEV** | Ultime 10 aggiunte a KEV: CVE, vendor, prodotto, data aggiunta, scadenza (`dueDate`), uso ransomware. | Click → dettaglio CVE |
| **Top gruppi ransomware** | Barre orizzontali, top 10 per numero di vittime nel periodo, con variazione vs periodo precedente. | Click → dashboard Gruppo |
| **Settori colpiti** | Barre orizzontali delle vittime per settore (dove la fonte lo fornisce; "Non specificato" separato). | Click → dashboard Settore |
| **Famiglie malware più attive** | Top 10 famiglie per nuovi IOC nel periodo (tag/famiglia da ThreatFox, MalwareBazaar, URLhaus). | Click → dashboard Famiglia |
| **IOC per tipo e fonte** | Barre impilate: tipo (IP, dominio, URL, hash) × fonte. | Click → elenco IOC filtrato |
| **Top vendor/prodotti** | Vendor con più CVE critiche e più KEV nel periodo. | Click → dashboard Vendor |
| **Bollettini CSIRT Italia** | Ultimi 10 avvisi dal feed RSS di CSIRT Italia: titolo, data, CVE citate (estratte dal testo) con indicazione se sono in KEV. | Click → avviso originale sul sito ACN; click su una CVE → dettaglio CVE |
| **Pulse OTX recenti** | Ultimi pulse dei feed sottoscritti: titolo, autore, tag, numero di indicatori. | Click → dettaglio pulse |

### 4.5 Intel feed

Stream cronologico unificato degli eventi provenienti da tutte le fonti, sempre visibile nella dashboard globale e disponibile anche come pagina a schermo intero.

**Tipi di evento (MVP):**

| Tipo | Generato quando | Severità di default |
|------|-----------------|---------------------|
| `cve.published` | Nuova CVE con CVSS ≥ 7.0. Le CVE sotto soglia non entrano nel feed ma restano consultabili. | Critica se ≥ 9.0, altrimenti Alta |
| `kev.added` | Nuova voce KEV | Critica |
| `epss.spike` | Il punteggio EPSS di una CVE supera la soglia o sale di almeno 0.2 in un giorno | Alta |
| `ransomware.victim` | Nuova vittima (prima segnalazione da qualunque fonte). Le segnalazioni successive della stessa vittima da altre fonti aggiornano l'evento esistente invece di crearne uno nuovo. | Alta se nel paese di interesse o in un topic seguito, altrimenti Media |
| `ioc.c2` | Nuovo C2 (Feodo Tracker, ThreatFox `botnet_cc`) | Alta |
| `ioc.batch` | Nuovi IOC dallo stesso run e dalla stessa famiglia o evento MISP, aggregati in un unico evento | Media |
| `otx.pulse` | Nuovo pulse sottoscritto | Media |
| `csirt.advisory` | Nuovo avviso nel feed RSS di CSIRT Italia | Alta se cita una CVE in KEV o parla di sfruttamento attivo, altrimenti Media |

**Ogni elemento del feed mostra:** icona della fonte, severità, titolo sintetico, timestamp (relativo con assoluto al passaggio del mouse), entità collegate come chip cliccabili (CVE, vendor, gruppo, paese, famiglia) e link alla fonte originale.

**Filtri:** tipo evento, severità minima, fonte, "solo i miei topic", testo libero. I filtri si riflettono nell'URL, così una vista filtrata è condivisibile.

**Aggiornamento:** polling ogni 60 secondi con indicatore "N nuovi eventi" (senza far saltare la lista). Il push via SSE/WebSocket è fuori MVP.

**Regole anti-rumore:** deduplica per (tipo, entità) entro 24h; gli IOC massivi si aggregano in `ioc.batch`; una CVE che entra in KEV produce un solo evento `kev.added` che aggiorna la card `cve.published` esistente; una vittima ransomware segnalata da più fonti resta un solo evento, che elenca le fonti.

### 4.6 Vista Fonti

Pagina dedicata, raggiungibile anche cliccando l'indicatore di freschezza. Visibile a tutti i ruoli.

| Colonna | Contenuto |
|---------|-----------|
| Fonte | Nome e collector (es. *abuse.ch – ThreatFox*) |
| Tipo | Periodico o Listener (esecuzione continua) |
| Stato | OK / in ritardo / errore / disabilitata (chiave mancante) / disabilitata da Admin. Per i listener: connesso / in riconnessione |
| Ultimo aggiornamento | Data e ora dell'ultimo run riuscito (o dell'ultimo messaggio ricevuto, per i listener) e prossimo run previsto |
| Record | Record letti, nuovi, aggiornati nell'ultimo run |
| Licenza | Tipo di licenza o condizioni d'uso, con link ai termini |
| Uso commerciale | **Sì** / **No** / **Da verificare**, con nota esplicativa |
| Quota | Limite d'uso dichiarato dalla fonte (es. richieste al minuto o al mese) e, dove misurabile, consumo attuale |
| Classe dati | Pubblico / Interno / Sensibile |
| Attribuzione | Testo di attribuzione richiesto dalla fonte, se previsto |

Le fonti con uso commerciale **No** o **Da verificare** sono evidenziate. Gli Admin vedono in più lo storico dei run, gli ultimi errori, il pulsante per forzare un aggiornamento e una sezione **Stato sistema** con l'esito dell'ultimo backup (in errore se fallito o più vecchio di 26 ore); nessuno vede il valore delle chiavi, solo se sono configurate.

Le attribuzioni richieste dalle fonti (es. NVD) sono riportate anche in una pagina "Fonti e licenze" accessibile dal footer.

## 5. Dashboard di argomento

Ogni entità principale ha una dashboard dedicata con lo stesso stile della globale, ma filtrata sull'argomento.

### 5.1 Tipi predefiniti

| Tipo | Chiave | KPI specifici | Pannelli |
|------|--------|---------------|----------|
| **Vendor / Prodotto** | vendor (+ prodotto opzionale), da CPE NVD e campi KEV | CVE nel periodo, critiche, KEV totali e nuove, EPSS medio dei top 10 | CVE prioritarie del vendor, timeline CVE/KEV, prodotti più colpiti, feed filtrato |
| **CVE** | CVE ID | Livello di priorità con motivo (§6), CVSS (vettore), EPSS e percentile, stato KEV, scadenza KEV | Descrizione, CWE, prodotti affetti (CPE), storico EPSS (grafico), riferimenti, avvisi CSIRT Italia, pulse OTX e IOC collegati, feed |
| **Gruppo ransomware** | nome gruppo | Vittime nel periodo e totali, paesi colpiti, prima e ultima attività | Timeline vittime, mappa vittime, settori, ultime vittime (con le fonti che le hanno segnalate), CVE associate se disponibili |
| **Famiglia malware** | nome famiglia normalizzato | Nuovi IOC, C2 attivi, campioni (MalwareBazaar) | IOC per tipo, ultimi C2, mappa infrastruttura, pulse OTX collegati |
| **Paese** | ISO 3166-1 alpha-2 | Vittime ransomware, gruppi attivi, IOC ospitati | Gruppi più attivi, settori, ultime vittime, infrastruttura ospitata |
| **Settore** | settore normalizzato | Vittime, gruppi attivi, paesi | Gruppi, paesi, ultime vittime |

### 5.2 Topic personalizzati

Un **topic** è un insieme salvato di criteri, creato da un Analyst, che genera una dashboard propria. I criteri sono in **AND** tra categorie diverse e in **OR** all'interno della stessa categoria:

- vendor/prodotti, CVE specifiche, CWE
- gruppi ransomware, famiglie malware
- paesi, settori
- parole chiave (cercate in descrizioni CVE, titoli e tag dei pulse)
- soglie (es. CVSS ≥ 8, EPSS ≥ 0.3)

Esempio: *"Sanità Italia"* = paese `IT` AND settore `Healthcare`.
Esempio: *"Edge devices"* = vendor ∈ {Fortinet, Ivanti, Palo Alto Networks, Citrix} AND (in KEV OR EPSS ≥ 0.3).

**Funzioni:**
- **Visibilità:** privato oppure condiviso con il team.
- **Segui:** l'utente può seguire un topic. Gli eventi che lo riguardano vengono evidenziati nel feed globale e ottengono la severità "Alta" minima.
- La dashboard di un topic usa un layout generico: KPI aggregati, feed filtrato, CVE prioritarie, vittime e IOC che rispettano i criteri.
- Anteprima del numero di risultati mentre si definiscono i criteri.

## 6. Livelli di priorità delle CVE

Le CVE vengono ordinate per **livelli**, non con un punteggio pesato. Ogni CVE appartiene al primo livello di cui soddisfa la condizione:

| Livello | Etichetta | Condizione |
|---------|-----------|------------|
| **P1** | Sfruttata da ransomware | In KEV con `knownRansomwareCampaignUse = Known` |
| **P2** | Sfruttata attivamente | In KEV |
| **P3** | Sfruttamento probabile | EPSS ≥ soglia (default 0.5, configurabile) |
| **P4** | Per gravità | Tutte le altre |

**Ordinamento dentro ciascun livello:**
- P1 e P2: data di aggiunta a KEV (più recente prima), poi EPSS decrescente, poi CVSS decrescente.
- P3: EPSS decrescente, poi CVSS decrescente.
- P4: CVSS decrescente, poi EPSS decrescente. Le CVE senza CVSS vanno in fondo.

**Motivo.** Il dettaglio CVE e il pannello "CVE prioritarie" mostrano il livello e una frase che spiega perché, costruita dai dati e non da un modello. Esempi:
- *P1 – In KEV dal 12/09/2026, uso in campagne ransomware: Known. EPSS 0.94 (99° percentile).*
- *P3 – Non in KEV. EPSS 0.62 (98° percentile), sopra la soglia 0.5. CVSS 8.8.*
- *P4 – Non in KEV, EPSS 0.03 sotto soglia. CVSS 9.8 (critica).*

Il livello si ricalcola a ogni aggiornamento di KEV o EPSS. Un cambio di livello verso l'alto genera l'evento del feed corrispondente (`kev.added` o `epss.spike`).

## 7. Requisiti non funzionali

- **Prestazioni:** la dashboard globale si carica in meno di 2 secondi a cache calda. Gli aggregati vengono precalcolati dopo ogni run dei collector, non a ogni richiesta.
- **Trasparenza:** ogni dato riporta la fonte e il link originale; ogni widget dichiara la freschezza dei dati.
- **Degrado controllato:** se una fonte non è disponibile o non ha la chiave, i widget che la usano mostrano lo stato invece di errori; il resto della dashboard funziona.
- **Tema:** scuro di default, chiaro disponibile.
- **Lingua:** UI in italiano nell'MVP, testi predisposti per l'inglese.
- **Accessibilità:** contrasti AA, legende testuali oltre ai colori, navigazione da tastiera.
- **Continuità:** backup giornaliero del database su un disco dedicato, separato dal disco di sistema della VM, con prova di ripristino documentata; si perde al massimo un giorno di dati (architettura §15).
- **Qualità del codice:** ogni modifica passa da una pull request verificata automaticamente (lint, tipi, test) prima del merge (architettura §14).

## 8. Fuori ambito (MVP)

- **Modulo Third-Party Risk**: confronto delle vittime ransomware con il registro fornitori aziendale. Il modello dati dell'MVP prevede già i campi di nome azienda e dominio normalizzati che serviranno al confronto (architettura §8.2).
- **Briefing AI**: sintesi periodica generata da un modello linguistico
- Le fonti della roadmap (§10) e l'arricchimento AI (nell'MVP esiste solo la classificazione dei dati su cui si baserà)
- Notifiche e alert (email, Teams, Slack, webhook)
- Push in tempo reale (SSE/WebSocket)
- Report PDF
- Integrazione MISP/OpenCTI e import/export STIX
- Arricchimento on-demand di IOC tramite fonti esterne (VirusTotal, Shodan, …): previsto dopo il rilascio (§10)
- Monitor dei leak di credenziali (IntelX, Dexpose): appartiene al futuro modulo Exposure (§10)
- Moduli di ricognizione attiva (gli script OSINT esistenti vengono eliminati, vedi architettura §12)
- Accesso con Entra ID (OIDC): è il **primo sviluppo dopo l'MVP**; l'MVP usa utenti locali

## 9. Criteri di accettazione

1. Con tutte le chiavi configurate, dopo il primo run completo, ogni KPI e pannello mostra dati coerenti con la fonte (verifica a campione su 3 valori per KPI).
2. Rimuovendo una chiave (es. OTX), la piattaforma si avvia, il collector risulta "disabilitato" e i widget OTX mostrano lo stato senza errori.
3. Ogni numero della dashboard globale porta a un elenco i cui elementi, contati, danno quel numero.
4. Cambiando periodo, tutti i widget si aggiornano in modo coerente.
5. Un Analyst crea il topic "Sanità Italia", lo condivide e un Viewer lo vede; il feed globale evidenzia gli eventi corrispondenti per chi lo segue.
6. Un Viewer non può creare topic né forzare run; un Admin sì, e l'azione compare nell'audit log.
7. La vista Fonti mostra per ogni collector licenza, uso commerciale e quota; abuse.ch, AlienVault OTX e CSIRT Italia risultano "Da verificare" finché le condizioni non sono confermate.
8. Senza `RANSOMWARE_LIVE_API_KEY` il collector ransomware.live risulta disabilitato e la piattaforma non usa l'API v2 gratuita.
9. Il dettaglio di una CVE in KEV con uso ransomware mostra livello P1 e il motivo; la stessa CVE è prima del pannello "CVE prioritarie" rispetto a una CVE con solo EPSS alto.
10. Una vittima segnalata da due fonti compare una sola volta, con entrambe le fonti elencate.

## 10. Roadmap fonti (fuori MVP)

Fonti previste dopo l'MVP. Il dettaglio tecnico è in [architettura §13](architettura.md).

| Fonte | Cosa porta | Classe dati | Note funzionali |
|-------|------------|-------------|-----------------|
| **Tenable.ONE** | Asset e vulnerabilità interne, in sola lettura | Interno | Vista "Esposizione interna" visibile solo con l'abilitazione dedicata Tenable: le CVE prioritarie (§6) incrociate con gli asset aziendali vulnerabili |
| **Arricchimento on-demand** (VirusTotal, Shodan) | Dal dettaglio di un IOC, un Analyst chiede il report di VirusTotal (hash, IP, dominio, URL) o i dati Shodan di un IP | Interno (le ricerche rivelano cosa sta indagando il team) | Il risultato arriva dopo qualche secondo, non in tempo reale. Solo consultazione di report esistenti: Specula non carica mai file o URL per l'analisi. Si inviano solo IOC pubblici, mai indirizzi privati o domini dell'organizzazione. Ogni richiesta è registrata nell'audit log, con un limite giornaliero per utente. Richiede un piano VirusTotal compatibile con l'uso aziendale |
| **Monitor dei leak** (IntelX, Dexpose) – modulo **Exposure** | Esposizione dei domini dell'organizzazione: dipendenti e utenti compromessi, log di infostealer, breach pubblici, con andamento nel tempo | Sensibile | Fa parte del modulo Exposure, con specifica propria. Mai password, hash o file delle macchine infette; email solo mascherate. Valutazione privacy prima dell'attivazione |
| **Telegram** | Messaggi di canali selezionati dagli Admin (solo testo e metadati) | Sensibile | Nessun media scaricato; i messaggi entrano nel feed solo come eventi collegati a entità note (CVE, gruppi, vittime) |
| **Arricchimento AI (ibrido)** | Traduzione in italiano, sintesi, estrazione di entità da testi (avvisi, pulse, messaggi) | Eredita la classe del dato di origine | I dati Pubblici possono essere elaborati da un provider remoto; i dati Interni e Sensibili (e quelli senza classe) solo dal modello locale sulla VM del LAB, che lavora su CPU, quindi con tempi più lunghi. Ogni invio a un provider remoto è registrato nell'audit log. Il contenuto generato è etichettato "generato da AI" e non sostituisce mai il dato originale |
