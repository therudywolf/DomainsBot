==========================================
BotTGDomains - Offline Deployment Package
==========================================

Этот архив содержит все необходимое для развертывания BotTGDomains на VM без интернета.

СОДЕРЖИМОЕ:
- images/          - Docker образы (tar файлы)
- project/         - Исходный код проекта
- deploy.sh        - Скрипт автоматического развертывания

ИНСТРУКЦИЯ ПО РАЗВЕРТЫВАНИЮ:

1. Распакуйте архив на целевой VM:
   tar -xzf bottgdomains-offline-*.tar.gz

2. Перейдите в директорию проекта:
   cd bottgdomains-offline-*/project

3. Запустите скрипт развертывания:
   ./deploy.sh

Или выполните шаги вручную:

1. Загрузите Docker образы:
   docker load -i ../images/gostsslcheck.tar
   docker load -i ../images/tgscanner.tar

2. Создайте файл .env:
   cp tg_domain_scanner_final/.env.example tg_domain_scanner_final/.env
   # Отредактируйте .env и укажите TG_TOKEN и ADMIN_ID

3. Запустите сервисы:
   docker-compose up -d

4. Проверьте статус:
   docker-compose ps
   docker-compose logs -f tgscanner

ТРЕБОВАНИЯ:
- Docker 20.10+
- Docker Compose 2.0+
- Linux система
- Минимум 5 GB свободного места на диске

ПОДДЕРЖКА:
См. DEPLOYMENT_OFFLINE.md для подробных инструкций.
