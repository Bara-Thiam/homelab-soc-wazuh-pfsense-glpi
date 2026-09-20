# Installation / guide de reproduction

Guide de mise en place du lab dans l'ordre suivi : réseau (pfSense + Suricata) → Wazuh Server → agent Windows 10 → GLPI. Voir [architecture.md](architecture.md) pour le détail des VM, IP et zones réseau avant de commencer.

## 1. pfSense — interfaces et zones réseau

Trois interfaces réseau, une par zone :

| Interface pfSense | Zone | Configuration |
|---|---|---|
| em0 | WAN | NAT, DHCP (adressage dynamique) |
| em1 | LAN-SERVEURS | 192.168.20.1/24 |
| em2 | LAN-UTILISATEURS | 192.168.30.1/24 |

Les règles de filtrage entre zones sont détaillées dans [architecture.md](architecture.md) (section "Filtrage réseau").

## 2. Suricata (package pfSense)

1. Installer le package **Suricata** via *System → Package Manager*.
2. Activer la sonde sur l'interface LAN-UTILISATEURS : *Services → Suricata → Interface Settings*, cliquer sur l'icône crayon de l'interface **LAN_UTILISATEURS** pour l'éditer.
3. Dans l'onglet **Categories** de cette interface, cocher `emerging-malware.rules` (ruleset ET Open) pour activer la signature SID 2025644 (voir [detection.md](detection.md)).

## 3. Wazuh Server (Ubuntu Server 24.04.4, 192.168.20.20)

### Installation (mode all-in-one, script officiel)

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Version installée : Wazuh 4.14.7.

### Règles custom

Les 3 règles custom (100501, 100201, 100502, décrites dans [detection.md](detection.md)) vont dans :

```
/var/ossec/etc/rules/local_rules.xml
```

Après toute modification de ce fichier, recharger la configuration :

```bash
sudo systemctl restart wazuh-manager
```

### Dépendances Python pour les scripts d'intégration

Les deux scripts d'intégration (`custom-response`, `custom-glpi`) ont chacun une dépendance externe. Elles ont été installées différemment, car le Python embarqué de Wazuh (`/var/ossec/framework/python/bin/python3`) n'a pas de `pip3` autonome accessible via `sudo pip3` :

```bash
# paramiko (custom-response), via apt, hors environnement Python de Wazuh
sudo apt install python3-paramiko -y

# requests (custom-glpi), directement dans l'environnement Python de Wazuh
sudo /var/ossec/framework/python/bin/python3 -m pip install requests
```

### Scripts d'intégration

Les scripts `custom-response` et `custom-glpi` (contenus détaillés dans [reponse-active.md](reponse-active.md) et [tracabilite-glpi.md](tracabilite-glpi.md)) vont dans :

```
/var/ossec/integrations/
```

Le nom du fichier doit correspondre exactement à la balise `<name>` du bloc `<integration>` associé dans `ossec.conf` (`custom-response`, `custom-glpi`, sans extension), avec les permissions suivantes :

```bash
sudo chmod 750 /var/ossec/integrations/custom-response /var/ossec/integrations/custom-glpi
sudo chown root:wazuh /var/ossec/integrations/custom-response /var/ossec/integrations/custom-glpi
```

Les deux blocs `<integration>` correspondants (avec les identifiants réels remplacés par des placeholders) sont détaillés dans [reponse-active.md](reponse-active.md) et [tracabilite-glpi.md](tracabilite-glpi.md).

## 4. Agent Windows 10 (192.168.30.10)

### Agent Wazuh

```powershell
$ProgressPreference = 'SilentlyContinue'

Invoke-WebRequest `
  -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

$msi = "$env:TEMP\wazuh-agent.msi"
$log = "$env:TEMP\wazuh-agent-install.log"

msiexec.exe /i $msi `
  /qn `
  /l*v $log `
  WAZUH_MANAGER="192.168.20.20" `
  WAZUH_REGISTRATION_SERVER="192.168.20.20" `
  WAZUH_AGENT_NAME="WIN10-CLIENT"
```

### Sysmon

Téléchargé depuis [Sysinternals](https://download.sysinternals.com/files/Sysmon.zip), extrait, puis installé avec une configuration minimale explicitement conçue pour tout inclure (aucune exclusion) sur les Event ID nécessaires à la détection (voir [detection.md](detection.md)) :

```powershell
$sysmonConfig = @"
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Event ID 1: ProcessCreate -->
    <ProcessCreate onmatch="exclude">
    </ProcessCreate>

    <!-- Event ID 3: NetworkConnect -->
    <NetworkConnect onmatch="exclude">
    </NetworkConnect>

    <!-- Event ID 11: FileCreate -->
    <FileCreate onmatch="exclude">
    </FileCreate>
  </EventFiltering>
</Sysmon>
"@

Set-Content -Path .\sysmon-minimal.xml -Value $sysmonConfig -Encoding UTF8
.\Sysmon64.exe -accepteula -i .\sysmon-minimal.xml
```

Un `onmatch="exclude"` avec une liste d'exclusion vide revient à tout journaliser pour cet Event ID : aucune règle ne matche pour exclure quoi que ce soit, donc tous les événements de ce type sont conservés.

### OpenSSH Server

Disponible en tant que fonctionnalité optionnelle Windows, activée directement lors de l'installation de la VM Windows 10 (case cochée dans les options d'installation), sans commande a posteriori.

## 5. GLPI (Ubuntu Server 24.04.4, 192.168.20.30, via Docker)

`/opt/glpi/docker-compose.yml` :

```yaml
services:
  glpi:
    image: "glpi/glpi:latest"
    restart: unless-stopped
    volumes:
      - glpi_data:/var/glpi
    env_file:
      - .env
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "80:80"

  db:
    image: "mysql"
    restart: unless-stopped
    volumes:
      - "./storage/mysql:/var/lib/mysql"
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: "yes"
      MYSQL_DATABASE: ${GLPI_DB_NAME}
      MYSQL_USER: ${GLPI_DB_USER}
      MYSQL_PASSWORD: ${GLPI_DB_PASSWORD}
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -u$$MYSQL_USER --password=$$MYSQL_PASSWORD"]
      start_period: 5s
      interval: 5s
      timeout: 5s
      retries: 10
    expose:
      - "3306"

volumes:
  glpi_data:
```

Un fichier `.env` (non versionné) définit `GLPI_DB_NAME`, `GLPI_DB_USER` et `GLPI_DB_PASSWORD`, consommés par le service `db`.

Démarrage :

```bash
cd /opt/glpi
sudo docker compose up -d
```

L'API REST GLPI, utilisée par `custom-glpi` (voir [tracabilite-glpi.md](tracabilite-glpi.md)), est exposée sur `http://192.168.20.30/api.php/v1`.