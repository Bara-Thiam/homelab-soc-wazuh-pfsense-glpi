# Troubleshooting

Cinq incidents significatifs rencontrés pendant la construction et l'exploitation du lab, documentés ici avec la démarche de diagnostic suivie plutôt que juste la solution finale — l'intérêt de ce fichier est autant le raisonnement que le correctif.

## 1. Fuite réseau via la carte hôte VMware (contournement de pfSense)

**Symptôme** : malgré des règles de filtrage pfSense correctes (LAN-UTILISATEURS → LAN-SERVEURS bloqué par défaut), Kali parvenait quand même à joindre Metasploitable2 (192.168.20.10) en ping, même avec une règle explicite `any/any` bloquant tout le trafic WAN entrant.

**Diagnostic** : un ping "réussi" affichait un TTL de 128 dans la réponse. Or Metasploitable2 tourne sous Linux (TTL par défaut 64) et pfSense sous FreeBSD (TTL par défaut 64 également) — même en traversant pfSense, la réponse aurait dû afficher un TTL proche de 61-63, pas 128 (TTL par défaut Windows). Ce détail a orienté le diagnostic vers la machine hôte Windows elle-même plutôt que vers une règle pfSense mal configurée.

**Cause réelle** : l'option "Connect a host virtual adapter to this network" avait été activée sur le VMnet2 (LAN-SERVEURS), pour permettre à l'hôte physique de se connecter en SSH/GUI aux serveurs (Wazuh, GLPI) sans avoir à tout configurer directement depuis l'intérieur de ces VM. Pour que cet accès fonctionne, une IP fixe avait été attribuée à cette carte hôte sur le sous-réseau 192.168.20.0/24. Or dès que Windows dispose d'une IP fixe sur ce sous-réseau, il crée automatiquement une route "directement connectée" pour tout le `/24` dans sa table de routage (`route print`). Le service NAT de VMware (`vmnat.exe`), qui s'appuie sur cette table de routage pour le trafic sortant des VM en NAT (dont Kali), utilisait alors cette route pour rediriger le trafic de Kali vers 192.168.20.0/24 directement via l'hôte — en contournant entièrement pfSense, qui ne voyait jamais ce trafic passer.

**Résolution** : remise de l'adressage de la carte hôte du VMnet2 en DHCP (sans IP fixe sur ce sous-réseau, donc sans route parasite créée), et ajout d'une VM dédiée, **Windows_Admin** (192.168.20.40, dans LAN-SERVEURS), pour reprendre le rôle d'accès GUI/SSH aux interfaces pfSense/Wazuh/GLPI que jouait auparavant l'hôte physique. Voir `architecture.md` pour le rôle final de Windows_Admin dans la topologie.

## 2. Corruption ZFS de pfSense après arrêt brutal

**Symptôme** : pfSense ne redémarrait plus, bloqué sur une erreur de boot (`zio_read error: 5`, `ZFS: i/o error - all block copies unavailable`, `ZFS: can't read MOS of pool pfSense`), suite à un arrêt brutal de la VM (probablement un crash ou un arrêt forcé plutôt qu'un shutdown propre).

**Diagnostic** : démarrage depuis l'ISO d'installation pfSense en mode Rescue Shell, puis tentative de diagnostic du pool ZFS :

```
zpool import
```

Résultat : le pool `pfSense` apparaissait en état `FAULTED`, avec le message `The pool Metadata is corrupted` (erreur ZFS-8000-72). Ce type d'erreur indique une corruption des métadonnées du pool, pas un simple verrou — l'import forcé (`-f`) ne répare pas ce genre de corruption, seulement les cas où le pool est actif ailleurs.

**Cause réelle** : ZFS, bien que plus robuste que UFS sur du matériel réel avec disques redondants, est plus sensible à la corruption après un arrêt brutal lorsqu'il tourne sur un disque virtuel unique sans la redondance qui le rend normalement résilient — configuration typique d'un lab VM.

**Résolution** : réinstallation complète de pfSense, avec le système de fichiers **UFS** choisi à la place de ZFS lors du partitionnement (plus simple et plus tolérant pour un disque virtuel unique). L'ensemble de la configuration (3 interfaces, adressage, règles de pare-feu, package Suricata) a dû être ressaisi intégralement, mais sans reconception : toute la configuration cible était déjà connue et documentée avant l'incident.

## 3. Windows Defender met en quarantaine le payload de façon récurrente

**Symptôme** : `phishing.exe` est détecté et neutralisé par Windows Defender lors de nombreux tests, malgré des tentatives répétées d'exécution du scénario. Un extrait de `Get-MpThreatDetection` sur Windows 10 montre des dizaines d'événements de détection sur `phishing.exe` (et des variantes comme `payload.exe`) étalés sur plusieurs semaines (fin août à début septembre 2026), avec des actions de quarantaine (`CleaningActionID: 2`) ou de suppression (`CleaningActionID: 9`) quasi systématiques, souvent en quelques secondes après dépôt ou exécution.

**Impact indirect** : cette détection répétée, découverte tardivement, explique une partie de l'incohérence de comportement observée d'une session de test à l'autre au fil du projet (le fichier "disparaissant" ou le scénario échouant sans raison apparente à certains moments).

**Résolution retenue** : plutôt que de contourner Defender techniquement (ce qui sortirait du périmètre du lab, axé sur la détection/réponse côté SOC et non sur l'évasion antivirus), Windows Defender est désactivé avant l'exécution du scénario. C'est documenté comme une simplification volontaire du lab dans `scenario-attaque.md`, pas comme une technique d'évasion : l'objectif est de valider la chaîne de détection Wazuh/Suricata (qui fonctionne indépendamment de Defender, via Sysmon/PowerShell logging), pas de démontrer un bypass AV.

## 4. Timeout SSH via `portfwd` sous trafic répété

Documenté directement dans `scenario-attaque.md` (étape 7, script de brute force) : le `ConnectTimeout` de `ssh` ne borne que l'établissement TCP, pas toute la négociation SSH à travers le tunnel `portfwd`, ce qui provoquait des blocages intermittents lors du brute force. Corrigé avec un `timeout 15` englobant toute la commande SSH et un `sleep 2` entre chaque tentative.

## 5. Active Response native Wazuh non fonctionnelle sur l'agent Windows

Résumé dans `reponse-active.md` ; détail complet de la séquence de débogage ici.

**Contexte** : avant d'adopter le mécanisme final (integration + script Python + SSH, voir `reponse-active.md`), une implémentation avec l'Active Response **native** de Wazuh a été mise en place : bloc `<active-response>`/`<command>` dans `ossec.conf` (`location: local`), script `block-wan.cmd` déployé sur l'agent Windows, déclenché par `wazuh-execd`.

**Bug 1 — configuration `ar.conf` obsolète en mémoire** : après ajout de la commande `block-wan` côté manager et resynchronisation de `ar.conf` vers l'agent (confirmée présente et à jour dans `C:\Program Files (x86)\ossec-agent\shared\ar.conf`), rien ne se déclenchait. Diagnostic : le service `WazuhSvc` tournait depuis avant la mise à jour de `ar.conf`, avec une définition de commandes obsolète chargée en mémoire (le service ne relit ce fichier qu'au démarrage, pas en continu). **Résolu** par un redémarrage complet du service (`Stop-Service` / `Start-Service`, pas un simple `Restart-Service`).

**Bug 2 — boucle `for /f ... in ('more')` bloquante** : une fois le redémarrage effectué, le script était enfin invoqué (`Script invoke` apparaissait dans les logs de debug), mais se bloquait immédiatement après, sans jamais lire l'entrée JSON. Cause : la commande batch `more`, utilisée pour lire `stdin`, attend indéfiniment une fin de flux propre que `wazuh-execd` ne fournissait pas de la façon attendue par ce pattern batch. **Résolu** en réécrivant le script en PowerShell (`[Console]::In.ReadToEnd()` pour lire tout `stdin` d'un coup, `ConvertFrom-Json` pour parser), avec `block-wan.cmd` conservé comme point d'entrée mais réduit à un simple relais vers ce script PowerShell.

**Bug 3 — silence inexpliqué de `wazuh-execd` côté agent (non résolu)** : malgré les deux corrections précédentes, confirmées individuellement fonctionnelles :
- le script (version PowerShell) s'exécute parfaitement quand on l'invoque manuellement avec un JSON identique à celui qu'enverrait Wazuh (séquence complète : `Script invoke` → `Input: {...}` → `Branche ADD` → `Actions terminees`) ;
- le manager envoie bien la commande à l'agent, confirmé par le log de debug `remoted` (`ar-forward.c:100 at AR_Forward(): DEBUG: Active response sent: ...`), aussi bien lors d'une vraie alerte que lors d'un déclenchement manuel via `agent_control -f` (contournant complètement le moteur de règles) ;

le déclenchement automatique par `wazuh-execd` sur l'agent Windows n'a jamais fonctionné. Aucune trace de réception ni de tentative d'exécution n'apparaît côté agent, même avec le niveau de debug maximal (`execd.debug=2`) — silence complet, sans erreur exploitable. Plusieurs pistes ont été écartées dans l'ordre avant d'en arriver là :
- configuration dupliquée/en conflit dans `ossec.conf` (fichier complet inspecté, structure saine, un seul bloc `<active-response>` actif) ;
- Windows Defender bloquant silencieusement le lancement du script (écarté : le test manuel prouve que le script s'exécute sans entrave une fois lancé) ;
- encodage du fichier `.cmd` avec BOM UTF-8 corrompant la première ligne (écarté : vérification des 3 premiers octets, `@echo` intact) ;
- service pare-feu Windows (`MpsSvc`) arrêté (non a été la cause ici, mais vérifié).

**Décision** : plutôt que de continuer à déboguer un mécanisme interne à Wazuh sans log exploitable côté agent (ce comportement correspond à des rapports non résolus documentant des soucis similaires avec l'Active Response native en `location: local` sur agent Windows, selon certaines versions de Wazuh), le déclencheur a été changé tout en réutilisant les composants déjà validés individuellement : le script de blocage fonctionnel a été conservé tel quel, mais invoqué via SSH/Paramiko depuis un script d'intégration Wazuh (mécanisme normalement prévu pour l'envoi d'alertes vers un système tiers), contournant entièrement `wazuh-execd` côté agent. C'est l'architecture documentée dans `reponse-active.md`.