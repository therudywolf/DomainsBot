#!/usr/bin/env bash
set -euo pipefail

# --- список доменов ---
if [ "$#" -gt 0 ]; then
  DOMAINS=("$@")
else
  DOMAINS=("crowdspace3.mos.ru" "mos.ru" "google.com")
fi

echo "▶ Проверяю: ${DOMAINS[*]}"
echo

for host in "${DOMAINS[@]}"; do
  # берём peer-cert + цепочку (15 с тайм-аут)
  chain=$(timeout 15s openssl s_client -connect "${host}:443" -servername "$host" \
          -showcerts </dev/null 2>/dev/null || true)

  if [[ -z $chain ]]; then
    printf "%-25s : connection error\n" "$host"
    continue
  fi

  verdict=""

  # 1) уже в хэндшейке видно GOST-шифры?
  if grep -qE "Cipher.*GOST" <<<"$chain"; then
    verdict="GOST cipher"
  fi

  # 2) раз-парсим каждый PEM-сертификат
  awk '
    /-----BEGIN CERTIFICATE-----/ {cert=$0; next}
    /-----END CERTIFICATE-----/   {print cert ORS $0; cert=""; next}
    {cert=cert ORS $0}
  ' <<<"$chain" | while read -r pem; do
      [[ -z $pem ]] && continue
      cert_txt=$(openssl x509 -noout -text 2>/dev/null <<<"$pem" || true)
      [[ -z $cert_txt ]] && continue

      [[ $cert_txt =~ (GOST[[:space:]]R|1\.2\.643\.) ]] && { verdict="GOST cert"; break; }
      [[ $cert_txt =~ (Russian[[:space:]]+Trusted|CryptoPro|Министерство|Минцифры) ]] && verdict="RUS CA"
  done

  [[ -z $verdict ]] && verdict="foreign CA"
  printf "%-25s : %s\n" "$host" "$verdict"
done
