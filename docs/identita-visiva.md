# Specula – Identità visiva e design token

> Stato: **APPROVATO – v1.0** (05/10/2026)
> Ambito: interfaccia di Specula Threat (MVP) e, in prospettiva, degli altri moduli Specula.
> Riferimento visivo: canvas Specula (tavola identità v1.1 e mockup della dashboard). Confronto effettuato: i valori di questo documento coincidono con il canvas.
> Documenti collegati: [specifica-funzionale-dashboard.md](specifica-funzionale-dashboard.md) · [piano-implementazione.md](piano-implementazione.md) (prerequisito di M5)

---

## 1. Nomi

| Nome | Uso |
|------|-----|
| **Specula** | La piattaforma. Compare nel marchio, nella schermata di login e nei materiali di brand. |
| **Specula Threat** | Il modulo di Threat Intelligence (MVP). Compare nell'intestazione dell'applicazione e nei titoli dei documenti. |
| Specula Exposure, Specula Third Party, Specula OSINT, Specula CLOSINT | Moduli futuri: nessun elemento di interfaccia finché non esiste una specifica approvata. |

## 2. Palette di brand

| Token | Nome | Valore | Uso |
|-------|------|--------|-----|
| `brand.navy` | Deep navy | `#0B1F3B` | Colore principale del marchio; testo su sfondo chiaro; superficie nel tema scuro |
| `brand.teal` | Petrol teal | `#0E6677` | Accento del marchio; link, azioni primarie e focus **su sfondo chiaro** |
| `brand.slate` | Steel slate | `#46556A` | Testo secondario e bordi dei controlli su sfondo chiaro; bordi decorativi nel tema scuro |
| `brand.mist` | Mist gray | `#8C98A5` | Su sfondo chiaro **solo linee e decorazioni, mai testo** (2,74:1 su ice white) |
| `brand.ice` | Ice white | `#F5F7FA` | Sfondo chiaro; testo principale nel tema scuro |

**Regole**
- Mist gray non si usa mai per testo su sfondo chiaro.
- Petrol teal non si usa mai per testo o dati su sfondo scuro (2,50:1 su `surface`). Nel tema scuro l'accento è `accent` (teal-300, `#3BB4C6`).

## 3. Tema scuro (default)

| Token | Valore | Uso |
|-------|--------|-----|
| `bg` | `#071426` | Sfondo della pagina |
| `surface` | `#0B1F3B` | Card, pannelli, tile KPI |
| `surface-2` | `#12294A` | Elementi sopra le card: intestazioni di tabella, hover, menu |
| `border` | `#46556A` | Bordi decorativi di card e pannelli |
| `divider` | `#1B3354` | **Solo separatori interni** (righe di tabella, divisioni dentro una card). Decorativo |
| `control-border` | `#8C98A5` (= `text-3`) | Contorno dei controlli: input, select, checkbox, radio |
| `focus` | `#3BB4C6` (= `accent`) | Indicatore di focus da tastiera |
| `text` | `#F5F7FA` | Testo principale, valori dei KPI |
| `text-2` | `#B7C1CC` | Testo secondario, etichette |
| `text-3` | `#8C98A5` | Testo terziario: metadati, timestamp, note |
| `accent` | `#3BB4C6` (teal-300) | Link, elemento attivo, serie principale dei grafici |

## 4. Tema chiaro

| Token | Valore | Uso |
|-------|--------|-----|
| `bg` | `#F5F7FA` (ice white) | Sfondo della pagina |
| `surface` | `#FFFFFF` | Card, pannelli, tile KPI |
| `surface-2` | `#E9EDF2` | Elementi sopra le card: intestazioni di tabella, hover, menu |
| `border` | `#8C98A5` (mist gray) | Separatori e bordi decorativi |
| `control-border` | `#46556A` (steel slate) | Contorno dei controlli: input, select, checkbox, radio |
| `focus` | `#0E6677` (= `accent`) | Indicatore di focus da tastiera |
| `text` | `#0B1F3B` (deep navy) | Testo principale |
| `text-2` | `#46556A` (steel slate) | Testo secondario |
| `text-3` | `#5B6878` | Testo terziario: metadati, timestamp, note |
| `accent` | `#0E6677` (petrol teal) | Link, elemento attivo, azioni primarie |
| `on-accent` | `#F5F7FA` (ice white) | Testo sopra pulsanti e badge con sfondo `accent` |

## 5. Severità e livelli di priorità

### 5.1 Colori di severità (badge e indicatori, entrambi i temi; grafici del tema scuro)

| Token | Etichetta | Valore | Livello CVE | Testo sopra |
|-------|-----------|--------|-------------|-------------|
| `sev.critical` | Critica | `#FF6B61` | P1 | `#071426` |
| `sev.high` | Alta | `#F5A524` | P2 | `#071426` |
| `sev.medium` | Media | `#E3CF5B` | P3 | `#071426` |
| `sev.low` | Bassa | `#8FB3D9` | P4 | `#071426` |

### 5.2 Varianti per i grafici del tema chiaro

| Token | Valore | Sfondi ammessi |
|-------|--------|----------------|
| `sev.chart-light.critical` | `#9E2A22` | `bg`, `surface`, `surface-2` |
| `sev.chart-light.high` | `#B85C00` | `bg`, `surface`, `surface-2` |
| `sev.chart-light.medium` | `#A08A00` | **solo `bg` e `surface`**, mai `surface-2` (2,91:1) |
| `sev.chart-light.low` | `#4A86C0` | `bg`, `surface`, `surface-2` |

**Regole**
- La severità è **sempre accompagnata dall'etichetta testuale** (es. badge "Critica" o "P1 · Critica"); il colore da solo non porta mai informazione.
- Il testo sopra un colore di severità (§5.1) è sempre `#071426`, in entrambi i temi.
- Le varianti §5.2 servono **solo per barre, linee, punti e aree dei grafici** del tema chiaro. **Non si usano per il testo**: tre su quattro sono sotto 4,5:1 (§9.3). Le etichette dei grafici usano `text` o `text-2`.
- Gli stessi colori valgono per i livelli P1–P4 (specifica §6) e per la severità degli eventi del feed (specifica §4.5). Il feed usa oggi Critica, Alta e Media; Bassa compare solo come P4.

## 6. Stato delle fonti

Token propri, **distinti dalle severità** anche quando condividono il valore: cambiare un colore di severità non cambia lo stato delle fonti, e viceversa.

| Token | Etichetta | Valore |
|-------|-----------|--------|
| `status.ok` | OK | `#3FB98A` |
| `status.late` | In ritardo | = `sev.high` (`#F5A524`) |
| `status.error` | Errore | = `sev.critical` (`#FF6B61`) |
| `status.disabled` | Disabilitata | = `text-3` del tema attivo |

**Regole**
- **Sempre con etichetta testuale** accanto all'indicatore (pallino o badge). Il testo dell'etichetta usa `text` o `text-2`, mai il colore di stato.
- In un badge pieno il testo sopra è `#071426`. `status.disabled` non si usa come sfondo di un badge: si mostra come testo `text-3` con l'etichetta "Disabilitata".
- Per distinguere a colpo d'occhio stato e severità (es. "In ritardo" e "Alta" hanno lo stesso colore), lo stato usa un **pallino** accanto all'etichetta, la severità un **badge** con l'etichetta dentro.

## 7. Scala sequenziale della mappa

| Token | Valore |
|-------|--------|
| `map.seq.1` | `#12294A` |
| `map.seq.2` | `#0E4F5E` |
| `map.seq.3` | `#0E6677` |
| `map.seq.4` | `#2A93A6` |
| `map.seq.5` | `#3BB4C6` |
| `map.seq.6` | `#9EE2EA` |

**Regole**
- `map.seq.1` è il valore più basso, `map.seq.6` il più alto.
- **Nessun dato** è reso con un **tratteggio** (pattern diagonale), distinto da qualunque classe della scala. Un paese con valore zero non è "nessun dato" (specifica §4.3).
- **Legenda sempre presente, con i valori** di ciascuna classe e la voce "Nessun dato" con il tratteggio.
- I confini dei paesi sono disegnati con `border`, così le classi più basse restano distinguibili dallo sfondo (§9.3).
- La mappa non si appoggia su `surface-2` del tema scuro: `map.seq.1` coincide con quel colore.

## 8. Tipografia e marchio

### 8.1 Font

| Font | Uso | Note |
|------|-----|------|
| **Montserrat** | Tutta l'interfaccia | Cifre tabulari (`font-variant-numeric: tabular-nums`) per KPI, tabelle e grafici, così i numeri restano allineati |
| **Playfair Display** | Solo schermata di login e materiali di brand | Mai nell'interfaccia operativa |
| **JetBrains Mono** | CVE ID, IOC, hash, domini, URL, indirizzi IP | Anche nei campi di ricerca quando si incolla un indicatore |

Tutti e tre i font sono distribuiti con licenza SIL Open Font License. Vanno inclusi nella build del frontend e non caricati da CDN esterne, perché la piattaforma gira nel LAB.

### 8.2 Marchio ridotto

- Tre forme: **tetto**, **base**, **punto centrale**.
- Due versioni: **chiara** (su sfondi scuri) e **scura** (su sfondi chiari).
- Deve restare leggibile fino a **16 px**, quindi è adatto anche come favicon e icona dell'intestazione.
- Il file vettoriale definitivo arriverà dal grafico. Fino ad allora l'applicazione usa un segnaposto e non va ridisegnato il marchio nel codice.

## 9. Verifica del contrasto (WCAG 2.x, livello AA)

Soglie AA: **4,5:1** per il testo normale, **3:1** per il testo grande (≥ 24 px, o ≥ 18,66 px in grassetto) e per i componenti grafici e i bordi necessari a riconoscere un controllo (criterio 1.4.11). Rapporti calcolati con la formula di luminanza relativa di WCAG 2.x.

### 9.1 Coppie testo/sfondo

**Tema scuro**

| Testo | su `bg` `#071426` | su `surface` `#0B1F3B` | su `surface-2` `#12294A` | Esito |
|-------|------|------|------|-------|
| `text` `#F5F7FA` | 17,21 | 15,37 | 13,57 | ✅ AA |
| `text-2` `#B7C1CC` | 10,13 | 9,04 | 7,99 | ✅ AA |
| `text-3` `#8C98A5` | 6,29 | 5,61 | 4,96 | ✅ AA |
| `accent` `#3BB4C6` | 7,50 | 6,70 | 5,92 | ✅ AA |

**Tema chiaro**

| Testo | su `bg` `#F5F7FA` | su `surface` `#FFFFFF` | su `surface-2` `#E9EDF2` | Esito |
|-------|------|------|------|-------|
| `text` `#0B1F3B` | 15,37 | 16,49 | 14,03 | ✅ AA |
| `text-2` `#46556A` | 7,07 | 7,59 | 6,45 | ✅ AA |
| `text-3` `#5B6878` | 5,29 | 5,68 | 4,83 | ✅ AA (margine minimo su `surface-2`) |
| `accent` `#0E6677` | 6,14 | 6,59 | 5,61 | ✅ AA |

**Testo sopra colori pieni**

| Testo | Sfondo | Rapporto | Esito |
|-------|--------|----------|-------|
| `on-accent` `#F5F7FA` | `accent` chiaro `#0E6677` | 6,14 | ✅ AA |
| `#F5F7FA` | `#0B1F3B` (navy, es. intestazione o login) | 15,37 | ✅ AA |
| `#F5F7FA` | `#46556A` (slate) | 7,07 | ✅ AA |
| `#071426` | `sev.critical` `#FF6B61` | 6,62 | ✅ AA |
| `#071426` | `sev.high` / `status.late` `#F5A524` | 9,05 | ✅ AA |
| `#071426` | `sev.medium` `#E3CF5B` | 11,73 | ✅ AA |
| `#071426` | `sev.low` `#8FB3D9` | 8,46 | ✅ AA |
| `#071426` | `status.ok` `#3FB98A` | 7,49 | ✅ AA |

**Risultato: tutte le coppie testo/sfondo dichiarate rispettano AA.** Il margine più stretto è `text-3` su `surface-2` nel tema chiaro (4,83:1).

### 9.2 Regole di divieto verificate

| Coppia vietata | Rapporto | Conferma |
|----------------|----------|----------|
| Mist gray `#8C98A5` su ice white `#F5F7FA` | 2,74 (2,94 su `surface`, 2,50 su `surface-2`) | ✅ Corretto vietarlo come testo |
| Petrol teal `#0E6677` su `surface` scuro `#0B1F3B` | 2,50 (2,80 su `bg`, 2,21 su `surface-2`) | ✅ Corretto vietarlo per testo e dati |
| `sev.chart-light.medium` `#A08A00` su `surface-2` chiaro | 2,91 | ✅ Corretto escluderlo da `surface-2` |

### 9.3 Componenti grafici (non testo, soglia 3:1)

| Elemento | `bg` | `surface` | `surface-2` | Esito |
|----------|------|-----------|-------------|-------|
| **Scuro** `control-border` `#8C98A5` | 6,29 | 5,61 | 4,96 | ✅ |
| **Scuro** `focus` `#3BB4C6` | 7,50 | 6,70 | 5,92 | ✅ |
| **Chiaro** `control-border` `#46556A` | 7,07 | 7,59 | 6,45 | ✅ |
| **Chiaro** `focus` `#0E6677` | 6,14 | 6,59 | 5,61 | ✅ |
| **Scuro** severità §5.1 (grafici e indicatori) | da 6,62 a 11,73 | da 5,91 a 10,48 | da 5,22 a 9,25 | ✅ |
| **Chiaro** `sev.chart-light.critical` `#9E2A22` | 6,97 | 7,48 | 6,36 | ✅ |
| **Chiaro** `sev.chart-light.high` `#B85C00` | 4,28 | 4,60 | 3,91 | ✅ (solo grafici, non testo) |
| **Chiaro** `sev.chart-light.medium` `#A08A00` | 3,19 | 3,43 | *escluso* | ✅ su `bg` e `surface` (solo grafici, non testo) |
| **Chiaro** `sev.chart-light.low` `#4A86C0` | 3,58 | 3,84 | 3,27 | ✅ (solo grafici, non testo) |
| **Scuro** `status.ok` `#3FB98A` | 7,49 | 6,69 | 5,91 | ✅ |
| **Chiaro** `status.ok` `#3FB98A` | 2,30 | 2,47 | 2,10 | ⚠️ sotto 3:1: ammesso solo perché affiancato dall'etichetta (§6) |
| **Chiaro** `status.late` / `status.error` | 1,90 / 2,60 | 2,04 / 2,79 | 1,74 / 2,37 | ⚠️ come sopra |
| **Scuro** `divider` `#1B3354` | 1,45 | 1,29 | 1,14 | ⚠️ sotto 3:1: corretto perché solo decorativo |
| **Scuro** `border` `#46556A` | 2,43 | 2,17 | 1,92 | ⚠️ solo decorativo; i controlli usano `control-border` |
| **Chiaro** `border` `#8C98A5` | 2,74 | 2,94 | 2,50 | ⚠️ solo decorativo; i controlli usano `control-border` |

**Scala della mappa**

| Classe | su `bg` scuro | su `surface` scuro | su `surface-2` scuro | vs classe precedente | su `bg` chiaro |
|--------|------|------|------|------|------|
| `map.seq.1` `#12294A` | 1,27 | 1,13 | 1,00 | — | 13,57 |
| `map.seq.2` `#0E4F5E` | 2,02 | 1,81 | 1,59 | 1,59 | 8,51 |
| `map.seq.3` `#0E6677` | 2,80 | 2,50 | 2,21 | 1,39 | 6,14 |
| `map.seq.4` `#2A93A6` | 5,12 | 4,57 | 4,04 | 1,83 | 3,36 |
| `map.seq.5` `#3BB4C6` | 7,50 | 6,70 | 5,92 | 1,46 | 2,29 |
| `map.seq.6` `#9EE2EA` | 12,77 | 11,40 | 10,07 | 1,70 | 1,35 |

Nel tema scuro le classi 1–3 sono sotto 3:1 rispetto allo sfondo, e le classi adiacenti sono tra 1,39 e 1,83:1 tra loro. È normale per una scala sequenziale, ed è compensato dalle regole del §7: confini con `border`, legenda con i valori, valore esatto al passaggio del mouse, tratteggio per "nessun dato". L'informazione non dipende quindi dalla sola distinzione dei colori.

## 10. Punti aperti (non bloccano M5)

1. **Cifre tabulari.** Verificare che la versione di Montserrat inclusa nella build supporti la funzione OpenType `tnum`.
2. **Marchio vettoriale.** In attesa del file definitivo dal grafico; fino ad allora si usa un segnaposto.

### Osservazione per il grafico (non bloccante)

La scala `map.seq` va dal colore più vicino allo sfondo scuro (basso) al più luminoso (alto), quindi è pensata per il tema scuro. Nel **tema chiaro** l'effetto si inverte: le classi basse sono le più marcate (13,57:1 su `bg`) e `map.seq.6` quasi sparisce (1,35:1). **Proposta provvisoria, da confermare con il grafico:** finché non esiste una scala per il tema chiaro, il riquadro della mappa mantiene lo sfondo `bg` del tema scuro anche nel tema chiaro.
