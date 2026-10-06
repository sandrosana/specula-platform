# Specula Threat – Runbook backup e ripristino

> Riferimento: [architettura.md §15](architettura.md). Comandi da eseguire sull'host del LAB (`cybertower`) dalla cartella del repository (`~/specula-platform`), salvo dove indicato.

## 1. Come funziona

- Il servizio `backup` del compose esegue ogni giorno alle `BACKUP_TIME` (default 02:30, fuso `Europe/Rome`) un `pg_dump --format=custom`, lo **cifra con `age`** usando la chiave pubblica `BACKUP_AGE_RECIPIENT` e lo salva in `/mnt/specula-backup` come `specula-AAAAMMGG-hhmm.dump.age`, con un file `.sha256` accanto.
- Il dump non viene mai scritto in chiaro: la cifratura avviene mentre il dump viene prodotto.
- **Retention:** gli ultimi 7 backup, più gli ultimi 4 della domenica. I più vecchi vengono cancellati dal job stesso.
- **Esito:** `last-backup.json` nella cartella dei backup (esito, ora, file, dimensione, durata) e log JSON del container. La vista "Stato sistema" per gli Admin arriva in M4.
- **Protezione dal disco non montato:** il job scrive solo se nella cartella esiste il file marcatore `.specula-backup-disk`, che si trova sul disco dati. Se il disco non è montato, `/mnt/specula-backup` è una cartella vuota sul disco di sistema e il job si rifiuta di scrivere.

## 2. Chiavi

| Chiave | Dove sta |
|--------|----------|
| Pubblica (`age1…`) | `.env` sull'host, variabile `BACKUP_AGE_RECIPIENT` |
| **Privata** (`AGE-SECRET-KEY-1…`) | **Solo fuori dall'host**: PC del responsabile (`%USERPROFILE%\.ssh\specula-backup-age.key`) e una copia in un luogo sicuro (password manager). **Senza la chiave privata i backup non si possono ripristinare.** |

La coppia attuale è stata generata il 06/10/2026 in un container temporaneo sull'host, senza scrivere su disco: la chiave privata è passata solo per la memoria dell'host ed è stata salvata direttamente sul PC (architettura §15.1).

## 3. Prima configurazione (una volta, da root)

```bash
touch /mnt/specula-backup/.specula-backup-disk
```

Poi in `.env` impostare `BACKUP_AGE_RECIPIENT` con la chiave pubblica e avviare lo stack:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

## 4. Backup manuale

```bash
docker compose --env-file .env -f deploy/docker-compose.yml run --rm backup backup.sh now
```

## 5. Prova di ripristino

La prova ripristina il dump in un PostgreSQL **temporaneo** dentro un container usa-e-getta (in memoria, mai nel database in uso), controlla il checksum e confronta versione delle migrazioni e numero di righe per tabella con il database in uso. La chiave privata arriva al container tramite lo standard input e non viene mai scritta su disco.

**Dal PC del responsabile** (PowerShell), con la chiave privata locale:

```powershell
Get-Content $env:USERPROFILE\.ssh\specula-backup-age.key | ssh -i $env:USERPROFILE\.ssh\specula_lab sandro@10.128.4.106 "cd ~/specula-platform && deploy/backup/verify-restore.sh latest"
```

Per un dump specifico sostituire `latest` con il nome del file.

**Esito atteso:** `RESULT: OK`. Una differenza nel numero di righe è normale se dopo il dump sono stati raccolti nuovi dati: viene segnalata ma non fa fallire la prova. Una versione delle migrazioni diversa, una tabella mancante, un checksum errato o un errore di decifratura o ripristino fanno fallire la prova.

**Quando:** al primo avvio, poi **una volta al mese** e dopo ogni aggiornamento di versione di PostgreSQL. Ogni prova va registrata nel §6.

## 6. Registro delle prove di ripristino

| Data | Dump | Durata | Esito | Note |
|------|------|--------|-------|------|
