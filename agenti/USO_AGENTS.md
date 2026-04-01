# Agenti ZBFOX

Wrapper operativi per usare i 3 pacchetti in modo uniforme.

## Componente unica

- `./agenti/zbfox_agent_orchestrator.sh`

## Routing

- `snapshot` -> `snapshot_agent.sh`
- `assessment` -> `security_assessment_agent.sh`
- `continuity` -> `protection_continuity_agent.sh`

## Esempi veloci

```bash
./agenti/zbfox_agent_orchestrator.sh snapshot init ACME external
./agenti/zbfox_agent_orchestrator.sh snapshot run /opt/zbfox/engagements/ZBF-SNAP-EXT-20260319-ACME
./agenti/zbfox_agent_orchestrator.sh assessment init ACME
./agenti/zbfox_agent_orchestrator.sh continuity compare-assessment --old /path/old --new /path/new --client ACME
```
