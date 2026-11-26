#!/bin/sh
# Wird beim Start des n8n-Containers ausgefuehrt:
# 1. legt die Ollama-Zugangsdaten mit der Adresse aus OLLAMA_URL an (gleicher Wert wie fuer die Module, siehe .env),
# 2. importiert die Workflows aus /workflows (n8n/workflows/*.json) und veroeffentlicht sie, damit ihre Zeitplaene laufen,
# 3. startet n8n wie gewohnt.
# Der Import laeuft bei jedem Start: Zugangsdaten und Workflows werden mit dem Stand aus dem Repository ueberschrieben.
# Aenderungen an Workflows in der Oberflaeche daher als JSON exportieren und nach n8n/workflows/ einchecken.

cat > /tmp/credentials.json <<EOF
[{"id":"argosOllama0001","name":"Ollama (Argos)","type":"ollamaApi","data":{"baseUrl":"${OLLAMA_URL}","apiKey":""}}]
EOF

n8n import:credentials --input=/tmp/credentials.json || echo "WARNUNG: Import der Ollama-Zugangsdaten fehlgeschlagen"

if ls /workflows/*.json >/dev/null 2>&1; then
  n8n import:workflow --separate --input=/workflows || echo "WARNUNG: Import der Workflows fehlgeschlagen"
  for f in /workflows/*.json; do
    # tr: unter Windows checkt Git die JSON-Dateien evtl. mit CRLF aus, sonst findet sed keine ID
    id=$(tr -d '\r' < "$f" | sed -n 's/^  "id": *"\([^"]*\)",\{0,1\} *$/\1/p' | head -n 1)
    if [ -n "$id" ]; then
      n8n publish:workflow --id="$id" || echo "WARNUNG: Workflow $id konnte nicht veroeffentlicht werden"
    else
      echo "WARNUNG: keine Workflow-ID in $f"
    fi
  done
fi

exec /docker-entrypoint.sh
