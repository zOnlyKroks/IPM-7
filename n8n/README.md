# n8n

Orchestrierung. Workflows als JSON in workflows/ ablegen (Export aus der n8n-Oberflaeche), damit sie im Repository liegen.
Das Verzeichnis ist im Container unter /workflows eingebunden, Import z. B. mit:

    docker compose exec n8n n8n import:workflow --separate --input=/workflows
