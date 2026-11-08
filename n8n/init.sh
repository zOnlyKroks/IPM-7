#!/bin/sh
# Wird beim Start des n8n-Containers ausgefuehrt: legt die Ollama-Zugangsdaten mit der Adresse aus OLLAMA_URL an
# (gleicher Wert wie fuer die Module, siehe .env) und startet danach n8n wie gewohnt.
# Der Import laeuft bei jedem Start und ueberschreibt die Zugangsdaten "Ollama (Argos)" mit dem Wert aus der .env.

cat > /tmp/credentials.json <<EOF
[{"id":"argosOllama0001","name":"Ollama (Argos)","type":"ollamaApi","data":{"baseUrl":"${OLLAMA_URL}","apiKey":""}}]
EOF

n8n import:credentials --input=/tmp/credentials.json || echo "WARNUNG: Import der Ollama-Zugangsdaten fehlgeschlagen"

exec /docker-entrypoint.sh
