# Traçabilité GLPI

Chaque alerte détectée (téléchargement du payload, reverse shell, brute force SSH, ou dépôt de fichier suspect) crée automatiquement un ticket GLPI, via le même mécanisme d'`<integration>` Wazuh utilisé pour la réponse active (voir [reponse-active.md](reponse-active.md)), mais ciblant ici l'API REST de GLPI plutôt qu'une connexion SSH.

```
Alerte Wazuh (100501, 100201, 100502 ou 92213) → integration → custom-glpi.py (Wazuh Server) → API REST GLPI → Ticket créé
```

## Configuration Wazuh (`ossec.conf`, bloc `<integration>`)

```xml
<integration>
  <name>custom-glpi</name>
  <hook_url>http://192.168.20.30/api.php/v1</hook_url>
  <api_key><app_token>|<user_token></api_key>
  <rule_id>100501,100201,100502,92213</rule_id>
  <alert_format>json</alert_format>
</integration>
```

Le champ `api_key` porte deux jetons distincts de l'API REST GLPI, séparés par `|` : l'`App-Token` (identifie l'application cliente) et le `User-Token` (identifie l'utilisateur GLPI au nom duquel les tickets sont créés). Les vrais jetons ne sont pas inclus dans ce dépôt.

## Script d'intégration (`custom-glpi`, Python, exécuté sur le Wazuh Server)

Le script suit le flux d'authentification standard de l'API REST GLPI en deux temps : ouverture d'une session (`initSession`) avec les deux jetons, puis création du ticket avec le `Session-Token` obtenu.

```python
#!/usr/bin/env python3
import sys
import json
import requests

alert_file = sys.argv[1]
api_key = sys.argv[2]      # format : "APP_TOKEN|USER_TOKEN"
hook_url = sys.argv[3]     # http://192.168.20.30/api.php/v1

app_token, user_token = api_key.split("|")

with open(alert_file) as f:
    lines = [l for l in f.read().splitlines() if l.strip()]
    alert = json.loads(lines[0])

rule = alert.get("rule", {})
agent = alert.get("agent", {})
mitre = rule.get("mitre", {})

ticket_name = f"[WAZUH] {rule.get('description', 'Alerte inconnue')}"
ticket_content = (
    f"Regle Wazuh : {rule.get('id')} (niveau {rule.get('level')})\n"
    f"Agent : {agent.get('name')} ({agent.get('ip')})\n"
    f"MITRE ATT&CK : {mitre.get('id', [])} - {mitre.get('technique', [])}\n"
    f"Horodatage : {alert.get('timestamp')}\n"
    f"Log complet : {alert.get('full_log', 'N/A')}"
)

headers_init = {
    "Content-Type": "application/json",
    "Authorization": f"user_token {user_token}",
    "App-Token": app_token,
}
r = requests.get(f"{hook_url}/initSession", headers=headers_init, timeout=10)
session_token = r.json().get("session_token")

headers_ticket = {
    "Content-Type": "application/json",
    "Session-Token": session_token,
    "App-Token": app_token,
}
payload = {"input": {"name": ticket_name, "content": ticket_content, "urgency": 5}}
requests.post(f"{hook_url}/Ticket", headers=headers_ticket, json=payload, timeout=10)
```

Chaque ticket créé contient : la règle Wazuh déclenchée (ID + niveau), l'agent concerné (nom + IP), le mapping MITRE ATT&CK, l'horodatage et le log brut de l'événement. L'urgence est fixée à 5 (maximale) pour toutes les alertes envoyées, sans distinction de niveau.

## Quatrième règle déclenchante : 92213 (native)

En plus des 3 règles custom déjà documentées dans [detection.md](detection.md), l'intégration GLPI se déclenche aussi sur la règle Wazuh native **92213** : "Executable file dropped in folder commonly used by malware" (niveau 15, groupe `sysmon_eid11_detections`, MITRE T1105 - Ingress Tool Transfer). Cette règle fait partie du ruleset Sysmon standard de Wazuh et détecte tout dépôt de fichier exécutable ou script dans un dossier temporaire habituellement utilisé pour l'exécution de malware (ex. `AppData\Local\Temp`), sans lien avec les règles custom du projet.

Un exemple capturé illustre bien la généricité de cette règle : elle s'est déclenchée non pas sur `phishing.exe` lui-même, mais sur `revert-block-wan.ps1`, le script de nettoyage créé automatiquement dans `Temp` par le mécanisme de réponse active du projet (voir [reponse-active.md](reponse-active.md)). Autrement dit, le propre mécanisme de remédiation du lab déclenche lui-même une détection native Wazuh, en plus de détecter l'attaque initiale — un exemple concret de dépôt de fichier suspect en Temp, indépendant de l'origine (légitime ou malveillante) du fichier.