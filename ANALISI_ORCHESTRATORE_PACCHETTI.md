# Analisi tecnica: orchestratore unico per i 3 pacchetti

## 1) Stato reale del repository analizzato

Nel repository corrente non è presente alcuna cartella `pacchetti/` né script CLI eseguibili relativi a:
- Snapshot
- Security Assessment
- Protection Continuity

Sono presenti invece solo pagine HTML/CSS di presentazione commerciale dei pacchetti.

### Evidenze
- `index.html` descrive i 3 pacchetti e i link di navigazione.
- `cyber-snapshot.html`, `cyber-security-assessment.html`, `cyber-protection-continuity.html` descrivono il contenuto dei servizi ma non contengono logica di orchestrazione script.

## 2) Valutazione della richiesta (fattibilità immediata)

La richiesta è architetturalmente sensata: un **launcher unico** riduce errori operativi e standardizza output/report.

Tuttavia, mancando gli script sorgente citati (es. `generate_block1`, parser XML OpenVAS, script finali dei pacchetti), non è possibile validare:
- firme reali dei comandi,
- nomi/percorsi effettivi degli artefatti,
- dipendenze runtime,
- gestione errori e idempotenza già implementata.

In altre parole: posso definire **design tecnico preciso** e suggerire implementazione, ma non posso garantire integrazione 1:1 senza i file mancanti.

## 3) Design consigliato dell'orchestratore unico

## Obiettivo UX
Un solo comando, ad esempio:

```bash
./pacchetti/run.sh
```

Prompt richiesti:
1. Nome Cliente
2. Scelta pacchetto con menu:
   - 1) Snapshot
   - 2) Security Assessment
   - 3) Protection Continuity

## Flussi richiesti (tradotti in pipeline tecniche)

### A) Snapshot
Input:
- modalità: INTERNAL / EXTERNAL
- target

Pipeline consigliata:
1. validazione target
2. creazione cartella output `report/<cliente>/snapshot/`
3. esecuzione script snapshot con i parametri
4. generazione report finale automatica

### B) Security Assessment
Input:
- target
- conferma fase 2 (report OpenVAS disponibile)

Pipeline consigliata:
1. genera sempre block1 con output fisso richiesto: `/report/block1.txt`
2. se confermata fase 2:
   - acquisisci path XML OpenVAS
   - parse XML -> genera blocco tecnico (block2)
   - usa path block1 richiesto dai tool successivi, es. `assessment/block1.md` (attenzione mismatch naming)
3. assembla report finale assessment

Nota critica da verificare nei tuoi script reali:
- hai indicato che `generate_block1` vuole destinazione finale `/report/block1.txt`,
- mentre block2 vuole `<blocks1_file>` pari a `assessment/.../block1.md`.

Questa divergenza (`.txt` vs `.md` e directory differente) va normalizzata con uno dei due approcci:
- **Approccio A**: generare block1 in `.md` già nel path definitivo;
- **Approccio B**: generare `/report/block1.txt` e poi convertire/copiarlo in `assessment/block1.md` prima di block2.

Senza normalizzazione, rischio alto di rottura in runtime.

### C) Protection Continuity
Input:
- posizione vecchia
- posizione nuova

Pipeline consigliata:
1. verifica esistenza input old/new
2. confronto delta (config/documentazione/output scansioni)
3. generazione report finale continuity in `report/<cliente>/continuity/`

## 4) Requisiti tecnici minimi da imporre

1. **Contratto I/O stabile** per ogni script:
   - input via argomenti CLI (`--client`, `--target`, ecc.)
   - output dichiarato (`--out`)
2. **Exit code standard**:
   - `0` ok
   - `!=0` errore con messaggio chiaro
3. **Log centralizzato**:
   - `report/<cliente>/logs/<timestamp>.log`
4. **Modalità non interattiva** opzionale:
   - utile per CI/CD (`--package 2 --target ... --openvas-xml ...`)
5. **Validazioni forti**:
   - target (hostname/IP/CIDR)
   - path XML esistente
   - directory output scrivibile

## 5) Rischi principali che vedo oggi

1. **Incoerenza path/formato block1** (`.txt` vs `.md`).
2. **Dipendenza temporale fase 2 assessment** (OpenVAS pronto/non pronto).
3. **Assenza naming convention report** (rischio sovrascrittura output).
4. **Mancanza script nel repo attuale**: blocco alla verifica end-to-end.

## 6) Implementazione pratica suggerita (quando carichi gli script)

Struttura proposta:

```text
pacchetti/
  run.sh
  common.sh
  snapshot/
    run_snapshot.sh
  assessment/
    generate_block1.sh
    parse_openvas_xml.sh
    generate_block2.sh
    compose_report.sh
  continuity/
    run_continuity.sh
report/
```

Responsabilità:
- `run.sh`: solo orchestrazione e prompt.
- script sotto-pacchetto: logica operativa singola.
- `common.sh`: validazioni, logging, utility path.

## 7) Conclusione operativa

La tua idea è corretta e consigliabile.

**Giudizio tecnico**: priorità alta, soprattutto per ridurre errori manuali nella catena Security Assessment (fase 1/fase 2 + parsing XML OpenVAS).

Per completare un'analisi realmente “su tutti gli script”, mi servono nel repository:
- cartella `pacchetti/`
- script reali richiamati (inclusi `generate_block1` e parser OpenVAS)
- un esempio XML OpenVAS di test

Con questi posso produrre: mappa completa dei flussi, refactor puntuale e orchestratore unico già funzionante.
