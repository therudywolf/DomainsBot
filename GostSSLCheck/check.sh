#!/usr/bin/env bash
set -euo pipefail

# Скрипт проверки GOST сертификатов доменов
# Использует OpenSSL с поддержкой GOST для проверки сертификатов

# --- список доменов ---
if [ "$#" -gt 0 ]; then
  DOMAINS=("$@")
else
  DOMAINS=("crowdspace3.mos.ru" "mos.ru" "google.com")
fi

# Функция для проверки одного домена
check_domain() {
  local host="$1"
  
  # Берём peer-cert + цепочку (15 с тайм-аут)
  local chain
  chain=$(timeout 15s openssl s_client -connect "${host}:443" -servername "$host" \
          -showcerts </dev/null 2>/dev/null || true)

  if [[ -z $chain ]]; then
    printf "%-25s : connection error\n" "$host"
    return 1
  fi

  local verdict=""

  # 1) Проверяем, видно ли GOST-шифры в хэндшейке?
  if grep -qE "Cipher.*GOST" <<<"$chain"; then
    verdict="GOST cipher"
  fi

  # 2) Разбираем каждый PEM-сертификат в цепочке
  awk '
    /-----BEGIN CERTIFICATE-----/ {cert=$0; next}
    /-----END CERTIFICATE-----/   {print cert ORS $0; cert=""; next}
    {cert=cert ORS $0}
  ' <<<"$chain" | while read -r pem; do
      [[ -z $pem ]] && continue
      
      # Парсим сертификат
      local cert_txt
      cert_txt=$(openssl x509 -noout -text 2>/dev/null <<<"$pem" || true)
      [[ -z $cert_txt ]] && continue

      # Проверяем на GOST алгоритм (OID 1.2.643.* или упоминание GOST)
      if [[ $cert_txt =~ (GOST[[:space:]]R|1\.2\.643\.) ]]; then
        verdict="GOST cert"
        break
      fi
      
      # Проверяем на российский CA
      if [[ $cert_txt =~ (Russian[[:space:]]+Trusted|CryptoPro|Министерство|Минцифры) ]]; then
        # Если еще не определили вердикт, ставим RUS CA
        [[ -z $verdict ]] && verdict="RUS CA"
      fi
  done

  # Если вердикт не определен, значит foreign CA
  [[ -z $verdict ]] && verdict="foreign CA"
  
  printf "%-25s : %s\n" "$host" "$verdict"
  return 0
}

# Проверяем каждый домен
for host in "${DOMAINS[@]}"; do
  check_domain "$host" || true
done
