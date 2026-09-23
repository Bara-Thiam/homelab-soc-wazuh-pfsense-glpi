# Homelab SOC — Wazuh / pfSense / Suricata / GLPI

Lab de sécurité auto-hébergé (7 VM, 3 zones réseau) reproduisant une chaîne SOC complète : un poste utilisateur compromis par phishing sert de point d'entrée vers un mouvement latéral et un brute force SSH sur un serveur legacy, avec détection réseau et hôte, réponse active automatisée, et traçabilité via ticketing.

## Résultats

- **8 étapes d'attaque** reproduites de bout en bout : phishing → reverse shell → découverte → scan ciblé → pivot → brute force SSH → connexion
- **4 mécanismes de détection indépendants** : 3 règles Wazuh custom (hôte) + 2 signatures Suricata convergentes (réseau)
- **Réponse active automatisée** : blocage réseau + kill process sur le poste compromis, déclenché sans intervention manuelle
- **Traçabilité complète** : chaque alerte crée automatiquement un ticket GLPI avec contexte MITRE ATT&CK
- **Pivot d'architecture documenté** : l'Active Response native de Wazuh s'est révélée non fonctionnelle sur agent Windows malgré une configuration conforme à la documentation ; contournement via une intégration SSH personnalisée (voir `docs/troubleshooting.md`)

## Architecture

3 zones réseau isolées par pfSense (pare-feu + NIDS Suricata) : WAN (attaquant), LAN-UTILISATEURS (poste victime), LAN-SERVEURS (SIEM, ticketing, cible legacy).

| VM | Rôle |
|---|---|
| pfSense 2.9.0 | Pare-feu, NAT, NIDS Suricata |
| Kali 2025.2 | Poste attaquant |
| Windows 10 | Poste victime (phishing) |
| Metasploitable2 | Cible legacy (SSH bruteforce) |
| Wazuh Server 4.14.7 | SIEM, orchestration réponse active |
| GLPI 11.0.8 | Ticketing / traçabilité |
| Windows_Admin | Accès GUI aux interfaces d'administration |

Détail complet (IP, filtrage réseau, décisions de conception) : [`docs/architecture.md`](docs/architecture.md)

## Scénario d'attaque

```
Phishing (msfvenom + Apache) → Reverse shell Meterpreter (port 4444)
  → Découverte d'hôtes (known_hosts) → Scan ciblé (Test-NetConnection)
  → Pivot (portfwd) → Brute force SSH (sshpass) → Connexion
```

Détail complet avec toutes les commandes : [`docs/scenario-attaque.md`](docs/scenario-attaque.md)

## Détection

| Étape | Mécanisme | Règle / Signature |
|---|---|---|
| Téléchargement + exécution payload | Wazuh (Sysmon/PowerShell) | 100501 |
| Ouverture reverse shell | Wazuh (Sysmon) + Suricata (signature + heuristique) | 100201, SID 2025644, SID 2260003 |
| Brute force SSH | Wazuh (fréquence) | 100502 |

**Mapping MITRE ATT&CK** : T1105 (Ingress Tool Transfer), T1571 (Non-Standard Port), T1110 (Brute Force)

Règles complètes (XML/Suricata) : [`docs/detection.md`](docs/detection.md)

## Réponse active et traçabilité

Chaque alerte critique déclenche en parallèle :
- un **blocage réseau automatique** sur le poste compromis (pare-feu Windows + kill process), via une intégration Wazuh personnalisée en SSH — voir [`docs/reponse-active.md`](docs/reponse-active.md)
- un **ticket GLPI** avec règle déclenchée, agent concerné, mapping MITRE et log brut — voir [`docs/tracabilite-glpi.md`](docs/tracabilite-glpi.md)

## Reproduire le lab

Guide complet d'installation (pfSense/Suricata, Wazuh Server, agent Windows, GLPI) : [`docs/installation.md`](docs/installation.md)

## Documentation complète

| Fichier | Contenu |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Zones réseau, VM, filtrage pfSense, décisions de conception |
| [`docs/scenario-attaque.md`](docs/scenario-attaque.md) | Les 8 étapes de l'attaque, commandes exactes |
| [`docs/detection.md`](docs/detection.md) | Règles Wazuh et signatures Suricata complètes |
| [`docs/reponse-active.md`](docs/reponse-active.md) | Mécanisme de réponse active et son architecture |
| [`docs/tracabilite-glpi.md`](docs/tracabilite-glpi.md) | Intégration GLPI et création de tickets |
| [`docs/installation.md`](docs/installation.md) | Guide de reproduction complet |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | Incidents rencontrés et démarche de diagnostic |

## Auteur

**Sereigne Bara Thiam**
L2 Génie Informatique, Réseaux Systèmes et Sécurité, ESITEC - Groupe Supdeco Dakar - 2025–2026
Projet réalisé dans le cadre d'un stage académique (juillet–septembre).

> *"Pour vraiment savoir comment attaquer, il faut comprendre comment fonctionne la défense."*