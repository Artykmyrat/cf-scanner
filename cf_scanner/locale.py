"""
cf_scanner.locale
==================
Мультиязычная поддержка (en, ru, tr).

Использование:
    from cf_scanner.locale import t, set_language
    set_language("ru")
    print(t("welcome"))  # "Добро пожаловать"
"""
from __future__ import annotations

from typing import Dict

_current_lang = "en"

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    # ======================================================================
    # Основные
    # ======================================================================
    "welcome": {
        "en": "Welcome to CF-Scanner Pro",
        "ru": "Добро пожаловать в CF-Scanner Pro",
        "tr": "CF-Scanner Pro'ya Hoş Geldiniz",
    },
    "exit": {
        "en": "Goodbye!",
        "ru": "До свидания!",
        "tr": "Görüşmek üzere!",
    },
    "press_enter": {
        "en": "Press Enter to continue",
        "ru": "Нажмите Enter для продолжения",
        "tr": "Devam etmek için Enter'a basın",
    },

    # ======================================================================
    # Главное меню
    # ======================================================================
    "menu_scan": {
        "en": "Start Scan",
        "ru": "Начать сканирование",
        "tr": "Tarama Başlat",
    },
    "menu_configs": {
        "en": "Configs (add / list / delete)",
        "ru": "Конфиги (добавить / список / удалить)",
        "tr": "Configler (ekle / listele / sil)",
    },
    "menu_settings": {
        "en": "Settings (Xray-Core, bad IP cache)",
        "ru": "Настройки (Xray-Core, кэш невалидных IP)",
        "tr": "Ayarlar (Xray-Core, bilinen-geçersiz IP hafızası)",
    },
    "menu_show_config": {
        "en": "Show config",
        "ru": "Показать конфигурацию",
        "tr": "Yapılandırmayı göster",
    },
    "menu_selection": {
        "en": "Selection",
        "ru": "Выбор",
        "tr": "Seçim",
    },
    "configs_registered": {
        "en": "configs registered",
        "ru": "конфигов зарегистрировано",
        "tr": "kayıtlı config",
    },
    "bad_ip_cache": {
        "en": "Bad IP cache",
        "ru": "Кэш невалидных IP",
        "tr": "Bilinen geçersiz IP",
    },

    # ======================================================================
    # Тип сканирования
    # ======================================================================
    "scan_type": {
        "en": "Scan Type",
        "ru": "Тип сканирования",
        "tr": "Tarama Türü",
    },
    "scan_cloudflare_only": {
        "en": "Cloudflare detection only (no config needed, checks if IP is behind Cloudflare)",
        "ru": "Только определение Cloudflare (конфиг не нужен, проверяет находится ли IP за Cloudflare)",
        "tr": "Sade Cloudflare tespiti (config gerekmez, sadece IP'nin Cloudflare arkasında olup olmadığına bakar)",
    },
    "scan_with_config": {
        "en": "Verify with config (VLESS/VMess/Trojan/Shadowsocks — Xray-Core or raw test)",
        "ru": "Проверка с конфигом (VLESS/VMess/Trojan/Shadowsocks — Xray-Core или raw тест)",
        "tr": "Config ile doğrulama (VLESS/VMess/Trojan/Shadowsocks — Xray-Core veya ham test)",
    },

    # ======================================================================
    # Конфиги
    # ======================================================================
    "configs_empty": {
        "en": "No configs yet",
        "ru": "Пока нет конфигов",
        "tr": "Henüz kayıtlı config yok",
    },
    "configs_add_new": {
        "en": "Let's add one now",
        "ru": "Давайте добавим один сейчас",
        "tr": "Hemen bir tane ekleyelim",
    },
    "configs_paste_link": {
        "en": "Paste a vless://, vmess://, trojan:// or ss:// link",
        "ru": "Вставьте ссылку vless://, vmess://, trojan:// или ss://",
        "tr": "vless://, vmess://, trojan:// veya ss:// linkini yapıştırın",
    },
    "configs_link": {
        "en": "Link",
        "ru": "Ссылка",
        "tr": "Link",
    },
    "configs_parse_error": {
        "en": "Could not parse link. Supported protocols: vless, vmess, trojan, ss.",
        "ru": "Не удалось распознать ссылку. Поддерживаемые протоколы: vless, vmess, trojan, ss.",
        "tr": "Link ayrıştırılamadı. Desteklenen protokoller: vless, vmess, trojan, ss.",
    },
    "configs_added": {
        "en": "Added",
        "ru": "Добавлен",
        "tr": "Eklendi",
    },
    "configs_fragment_detected": {
        "en": "Fragment detected",
        "ru": "Обнаружен Fragment",
        "tr": "Fragment algılandı",
    },
    "configs_table_title": {
        "en": "Registered Configs",
        "ru": "Зарегистрированные конфиги",
        "tr": "Kayıtlı Configler",
    },
    "configs_add": {
        "en": "Add config",
        "ru": "Добавить конфиг",
        "tr": "Yeni config ekle",
    },
    "configs_delete": {
        "en": "Delete config",
        "ru": "Удалить конфиг",
        "tr": "Config sil",
    },
    "configs_back": {
        "en": "Back",
        "ru": "Назад",
        "tr": "Geri",
    },
    "configs_delete_number": {
        "en": "Number to delete",
        "ru": "Номер для удаления",
        "tr": "Silinecek # numarası",
    },
    "configs_deleted": {
        "en": "Deleted",
        "ru": "Удалён",
        "tr": "Silindi",
    },
    "configs_invalid_number": {
        "en": "Invalid number",
        "ru": "Неверный номер",
        "tr": "Geçersiz numara",
    },
    "configs_nothing_to_delete": {
        "en": "No configs to delete",
        "ru": "Нечего удалять",
        "tr": "Silinecek config yok",
    },
    "configs_number": {
        "en": "#",
        "ru": "#",
        "tr": "#",
    },
    "configs_name": {
        "en": "Name",
        "ru": "Имя",
        "tr": "İsim",
    },
    "configs_detail": {
        "en": "Detail",
        "ru": "Детали",
        "tr": "Detay",
    },
    "configs_address": {
        "en": "Address",
        "ru": "Адрес",
        "tr": "Adres",
    },
    "configs_fragment": {
        "en": "Fragment",
        "ru": "Фрагмент",
        "tr": "Fragment",
    },

    # ======================================================================
    # Xray-Core
    # ======================================================================
    "xray_active": {
        "en": "active",
        "ru": "активен",
        "tr": "aktif",
    },
    "xray_inactive": {
        "en": "off / not found",
        "ru": "выкл / не найден",
        "tr": "kapalı / bulunamadı",
    },
    "xray_binary": {
        "en": "Binary",
        "ru": "Бинарник",
        "tr": "İkili dosya",
    },
    "xray_expected": {
        "en": "Expected file for this system",
        "ru": "Ожидаемый файл для этой системы",
        "tr": "Bu sistem için beklenen dosya",
    },
    "xray_download_page": {
        "en": "Official download page",
        "ru": "Официальная страница загрузки",
        "tr": "Resmi indirme sayfası",
    },
    "xray_bad_ip_memory": {
        "en": "Bad IP memory",
        "ru": "Память невалидных IP",
        "tr": "Bilinen-geçersiz IP hafızası",
    },
    "xray_records": {
        "en": "records",
        "ru": "записей",
        "tr": "kayıt",
    },
    "xray_contexts": {
        "en": "contexts",
        "ru": "контекстов",
        "tr": "bağlamda",
    },
    "xray_auto_expire": {
        "en": "older records auto-deleted",
        "ru": "старые записи удаляются автоматически",
        "tr": "30 günden eski kayıtlar otomatik silinir",
    },
    "xray_download_update": {
        "en": "Download / update Xray-Core",
        "ru": "Загрузить / обновить Xray-Core",
        "tr": "Xray-Core'u indir / güncelle",
    },
    "xray_manual_info": {
        "en": "Show manual download info",
        "ru": "Показать инструкцию по ручной загрузке",
        "tr": "Xray-Core manuel indirme bilgisi göster",
    },
    "xray_toggle": {
        "en": "Disable / re-enable Xray-Core for this session",
        "ru": "Отключить / включить Xray-Core для этой сессии",
        "tr": "Xray-Core'u bu oturumda devre dışı bırak / yeniden etkinleştir",
    },
    "xray_view_bad_cache": {
        "en": "View bad IP cache",
        "ru": "Просмотреть кэш невалидных IP",
        "tr": "Bilinen-geçersiz IP hafızasını görüntüle",
    },
    "xray_clear_bad_cache": {
        "en": "Clear bad IP cache",
        "ru": "Очистить кэш невалидных IP",
        "tr": "Bilinen-geçersiz IP hafızasını temizle",
    },
    "xray_downloading": {
        "en": "Downloading...",
        "ru": "Загрузка...",
        "tr": "İndiriliyor...",
    },
    "xray_download_success": {
        "en": "Success",
        "ru": "Успешно",
        "tr": "Başarılı",
    },
    "xray_manual_steps": {
        "en": "Manual Download Steps",
        "ru": "Шаги ручной загрузки",
        "tr": "Manuel İndirme Adımları",
    },
    "xray_disabled": {
        "en": "Xray-Core disabled for this session. Raw test mode will be used.",
        "ru": "Xray-Core отключён для этой сессии. Будет использоваться raw тест.",
        "tr": "Xray-Core bu oturum için devre dışı bırakıldı. Ham test ile devam edilecek.",
    },
    "xray_reenabled": {
        "en": "Xray-Core re-enabled",
        "ru": "Xray-Core снова включён",
        "tr": "Xray-Core tekrar etkinleştirildi",
    },
    "xray_not_found_download": {
        "en": "Binary not found, download first (Menu 1)",
        "ru": "Бинарник не найден, сначала загрузите (Меню 1)",
        "tr": "İkili dosya bulunamadı, önce indirin (Menü 1)",
    },
    "xray_cache_empty": {
        "en": "Cache is empty",
        "ru": "Кэш пуст",
        "tr": "Hafıza boş",
    },
    "xray_cache_table_title": {
        "en": "Known Bad IP Memory",
        "ru": "Память известных невалидных IP",
        "tr": "Bilinen-Geçersiz IP Hafızası",
    },
    "xray_cache_context": {
        "en": "Context",
        "ru": "Контекст",
        "tr": "Bağlam",
    },
    "xray_cache_count": {
        "en": "Record count",
        "ru": "Количество записей",
        "tr": "Kayıt sayısı",
    },
    "xray_cache_clear_confirm": {
        "en": "Delete all bad IP records? (next scan will re-test everything)",
        "ru": "Удалить все записи невалидных IP? (следующее сканирование проверит всё заново)",
        "tr": "Tüm bilinen-geçersiz IP kayıtları silinsin mi? (bir dahaki taramada her şey sıfırdan test edilir)",
    },
    "xray_cache_cleared": {
        "en": "records deleted",
        "ru": "записей удалено",
        "tr": "kayıt silindi",
    },

    # ======================================================================
    # Настройки (Xray download URL и т.д.)
    # ======================================================================
    "settings_manual_step1": {
        "en": "1) Open in browser",
        "ru": "1) Откройте в браузере",
        "tr": "1) Tarayıcıdan açın",
    },
    "settings_manual_step2": {
        "en": "2) Download",
        "ru": "2) Скачайте",
        "tr": "2) İndirin",
    },
    "settings_manual_step3": {
        "en": "3) Extract zip and put 'xray' binary in",
        "ru": "3) Распакуйте zip и поместите бинарник 'xray' в",
        "tr": "3) Zip'i açın, içindeki 'xray' dosyasını şu klasöre koyun",
    },
    "settings_manual_step4": {
        "en": "4) On Linux/Mac/Termux grant execute permission",
        "ru": "4) На Linux/Mac/Termux дайте права на исполнение",
        "tr": "4) Linux/Mac/Termux'ta çalıştırma izni verin",
    },

    # ======================================================================
    # Цели (ASN, CIDR)
    # ======================================================================
    "targets_title": {
        "en": "Targets",
        "ru": "Цели",
        "tr": "Hedefler",
    },
    "targets_hint": {
        "en": "fill at least one — you can use both together",
        "ru": "заполните хотя бы одно — можно использовать оба вместе",
        "tr": "en az birini doldurun — ikisini birlikte de kullanabilirsiniz",
    },
    "targets_asn": {
        "en": "ASN (e.g. AS13335 = Cloudflare) — leave empty to skip",
        "ru": "ASN (напр. AS13335 = Cloudflare) — оставьте пустым чтобы пропустить",
        "tr": "ASN (örn. AS13335 = Cloudflare) — atlamak için boş geçin",
    },
    "targets_cidr": {
        "en": "Extra CIDR/IP list, comma-separated (e.g. 188.114.96.0/24, 1.1.1.1) — leave empty to skip",
        "ru": "Дополнительный список CIDR/IP через запятую (напр. 188.114.96.0/24, 1.1.1.1) — оставьте пустым чтобы пропустить",
        "tr": "Ek CIDR/IP listesi, virgülle ayırın (örn. 188.114.96.0/24, 1.1.1.1) — atlamak için boş geçin",
    },
    "targets_fetching": {
        "en": "Fetching prefixes from RIPEstat",
        "ru": "Получение префиксов из RIPEstat",
        "tr": "RIPEstat'tan prefixler çekiliyor",
    },
    "targets_fetch_error": {
        "en": "Could not fetch data from RIPE",
        "ru": "Не удалось получить данные из RIPE",
        "tr": "RIPE'tan veri alınamadı",
    },
    "targets_not_found": {
        "en": "No prefixes found, skipping",
        "ru": "Префиксы не найдены, пропускается",
        "tr": "Prefix bulunamadı, atlanıyor",
    },
    "targets_blocks": {
        "en": "prefixes → /24 blocks",
        "ru": "префиксов → /24 блоков",
        "tr": "prefix → /24 blok",
    },
    "targets_manual_blocks": {
        "en": "manually entered blocks",
        "ru": "введённых вручную блоков",
        "tr": "elle girilen blok",
    },
    "targets_no_valid": {
        "en": "No valid targets entered, scan cannot start.",
        "ru": "Не введено ни одной валидной цели, сканирование невозможно.",
        "tr": "Hiçbir geçerli hedef girilmedi, tarama başlatılamıyor.",
    },
    "targets_invalid_cidr": {
        "en": "Invalid IP/CIDR skipped",
        "ru": "Неверный IP/CIDR пропущен",
        "tr": "Geçersiz IP/CIDR atlandı",
    },
    "targets_total": {
        "en": "total blocks, scanning",
        "ru": "всего блоков, сканирование",
        "tr": "toplam blok, taranacak",
    },
    "targets_ip_count": {
        "en": "IPs",
        "ru": "IP",
        "tr": "IP",
    },

    # ======================================================================
    # Xray выбор
    # ======================================================================
    "xray_ask_verify": {
        "en": "Perform 100% REAL tunnel test with Xray-Core?",
        "ru": "Выполнить 100% РЕАЛЬНЫЙ тест туннеля через Xray-Core?",
        "tr": "Xray-Core ile %100 GERÇEK tünel testi yapılsın mı?",
    },
    "xray_ask_verify_hint": {
        "en": "(No = faster but less reliable raw TLS test)",
        "ru": "(Нет = быстрее, но менее надёжный raw TLS тест)",
        "tr": "(Hayır = daha hızlı ama daha az kesin ham TLS testi)",
    },
    "xray_unavailable": {
        "en": "Xray-Core unavailable (download in Settings). Continuing with raw test.",
        "ru": "Xray-Core недоступен (загрузите в Настройках). Продолжаем с raw тестом.",
        "tr": "Xray-Core şu an kullanılamıyor (Ayarlar'dan indirebilirsiniz). Ham test ile devam edilecek.",
    },
    "xray_raw_warning": {
        "en": "This config uses xhttp + alpn=h3 — Xray-core carries it over REAL QUIC/UDP, not TCP. "
             "'Raw test' mode does TCP TLS handshake, so it cannot fully verify this config "
             "(may give false positives/negatives). For definitive results, use Xray-Core full tunnel mode.",
        "ru": "Этот конфиг использует xhttp + alpn=h3 — Xray-core передаёт его через НАСТОЯЩИЙ QUIC/UDP, а не TCP. "
              "'Raw тест' делает TCP TLS handshake, поэтому не может полностью проверить этот конфиг "
              "(может дать ложные результаты). Для точных результатов используйте режим полного туннеля Xray-Core.",
        "tr": "Bu config xhttp + alpn=h3 kullanıyor — "
              "Xray-core bunu TCP değil GERÇEK QUIC/UDP ile taşır. 'Ham test' "
              "modu TCP üzerinden TLS el sıkışması yaptığı için bu configi "
              "%100 doğrulayamaz (yanlış-pozitif/negatif verebilir). "
              "Kesin sonuç için Xray-Core tam tünel modunu kullanmanız önerilir.",
    },
    "xray_raw_continue": {
        "en": "Continue with raw test mode anyway?",
        "ru": "Всё равно продолжить в режиме raw теста?",
        "tr": "Yine de ham test moduyla devam edilsin mi?",
    },
    "xray_cancelled": {
        "en": "Cancelled. Download Xray-Core in Settings if needed.",
        "ru": "Отменено. Загрузите Xray-Core в Настройках при необходимости.",
        "tr": "İptal edildi, Xray-Core kullanılamıyorsa Ayarlar'dan indirebilirsiniz.",
    },

    # ======================================================================
    # Параметры сканирования
    # ======================================================================
    "scan_max_results": {
        "en": "Stop scan after how many verified IPs? (0 = scan all)",
        "ru": "Остановить сканирование после скольки проверенных IP? (0 = все)",
        "tr": "Kaç IP doğrulanınca tarama otomatik dursun? (0 = tümünü tara)",
    },
    "scan_advanced_settings": {
        "en": "Show advanced settings? (defaults are usually fine)",
        "ru": "Показать расширенные настройки? (обычно достаточно стандартных)",
        "tr": "Gelişmiş ayarları göstermek ister misiniz? (varsayılanlar genelde yeterlidir)",
    },
    "scan_ports": {
        "en": "Ports to scan",
        "ru": "Порты для сканирования",
        "tr": "Taranacak port(lar)",
    },
    "scan_tcp_workers": {
        "en": "Concurrent TCP pre-filter workers",
        "ru": "Количество параллельных TCP воркеров",
        "tr": "Eşzamanlı TCP ön-filtre işçi sayısı",
    },
    "scan_deep_concurrency": {
        "en": "Deep verification concurrency",
        "ru": "Количество воркеров глубокой проверки",
        "tr": "Derin doğrulama eşzamanlılığı",
    },
    "scan_deep_concurrency_xray": {
        "en": "Deep verification concurrency (each opens a separate Xray-Core process)",
        "ru": "Количество воркеров глубокой проверки (каждый запускает отдельный процесс Xray-Core)",
        "tr": "Derin doğrulama eşzamanlılığı (her biri ayrı bir Xray-Core süreci açar)",
    },
    "scan_result_file": {
        "en": "Result file",
        "ru": "Файл результатов",
        "tr": "Sonuç dosyası",
    },

    # ======================================================================
    # Результаты (resume / new)
    # ======================================================================
    "results_already_exist": {
        "en": "already has verified IPs",
        "ru": "уже содержит проверенные IP",
        "tr": "dosyasında zaten doğrulanmış IP var",
    },
    "results_continue_or_new": {
        "en": "Continue on existing records (old ones skipped, not re-tested) or start a new file?",
        "ru": "Продолжить с существующими записями (старые пропускаются) или начать новый файл?",
        "tr": "Bu kayıtların üzerine devam edilsin mi (eskiler atlanır, tekrar test edilmez) "
             "yoksa yeni bir dosyaya mı başlansın?",
    },
    "results_continue": {
        "en": "continue",
        "ru": "продолжить",
        "tr": "devam",
    },
    "results_new": {
        "en": "new",
        "ru": "новый",
        "tr": "yeni",
    },
    "results_new_file": {
        "en": "New file",
        "ru": "Новый файл",
        "tr": "Yeni dosya",
    },

    # ======================================================================
    # Сканирование (статусы, панели)
    # ======================================================================
    "scan_stopping": {
        "en": "STOPPING",
        "ru": "ОСТАНОВКА",
        "tr": "DURDURULUYOR",
    },
    "scan_scanning": {
        "en": "SCANNING",
        "ru": "СКАНИРОВАНИЕ",
        "tr": "TARANIYOR",
    },
    "scan_target": {
        "en": "Target",
        "ru": "Цель",
        "tr": "Hedef",
    },
    "scan_mode": {
        "en": "Mode",
        "ru": "Режим",
        "tr": "Mod",
    },
    "scan_config": {
        "en": "Config",
        "ru": "Конфиг",
        "tr": "Config",
    },
    "scan_xray": {
        "en": "Xray-Core",
        "ru": "Xray-Core",
        "tr": "Xray-Core",
    },
    "scan_alive_ports": {
        "en": "alive ports",
        "ru": "живых портов",
        "tr": "canlı port",
    },
    "scan_verified": {
        "en": "verified",
        "ru": "проверено",
        "tr": "doğrulanan",
    },
    "scan_skipped_cache": {
        "en": "skipped (cache)",
        "ru": "пропущено (кэш)",
        "tr": "geçersiz(önbellek)",
    },
    "scan_skipped_previous": {
        "en": "skipped (previous)",
        "ru": "пропущено (ранее)",
        "tr": "atlandı(önceki)",
    },
    "scan_testing": {
        "en": "Currently testing",
        "ru": "Сейчас тестируется",
        "tr": "Şu an test ediliyor",
    },
    "scan_verified_ips": {
        "en": "Verified IPs",
        "ru": "Проверенные IP",
        "tr": "Doğrulanan IP'ler",
    },
    "scan_no_verified_yet": {
        "en": "no verified IPs yet...",
        "ru": "пока нет проверенных IP...",
        "tr": "henüz doğrulanmış IP yok...",
    },
    "scan_ctrl_c": {
        "en": "Ctrl+C: stop immediately  •  results are saved in real-time",
        "ru": "Ctrl+C: мгновенная остановка  •  результаты сохраняются в реальном времени",
        "tr": "Ctrl+C: hemen durdur  •  sonuçlar anlık kaydediliyor",
    },
    "scan_known_bad_skip": {
        "en": "known bad IPs in memory, they will be skipped",
        "ru": "известных невалидных IP в памяти, они будут пропущены",
        "tr": "IP var, bunlar otomatik atlanacak",
    },

    # ======================================================================
    # Итоги сканирования
    # ======================================================================
    "summary_title": {
        "en": "Scan Summary",
        "ru": "Итоги сканирования",
        "tr": "Tarama Özeti",
    },
    "summary_scanned": {
        "en": "IPs scanned",
        "ru": "IP просканировано",
        "tr": "Taranan IP",
    },
    "summary_alive": {
        "en": "Alive ports found",
        "ru": "Живых портов найдено",
        "tr": "Canlı port bulunan",
    },
    "summary_verified": {
        "en": "Verified",
        "ru": "Проверено",
        "tr": "Doğrulanan",
    },
    "summary_skipped_cache": {
        "en": "Skipped (cache)",
        "ru": "Пропущено (кэш)",
        "tr": "Atlanan (önbellek)",
    },
    "summary_skipped_previous": {
        "en": "Skipped (previous)",
        "ru": "Пропущено (ранее)",
        "tr": "Atlanan (önceki sonuç)",
    },
    "summary_elapsed": {
        "en": "Total time",
        "ru": "Общее время",
        "tr": "Toplam süre",
    },
    "summary_speed": {
        "en": "IPs/sec",
        "ru": "IP/сек",
        "tr": "ip/s",
    },
    "summary_result_file": {
        "en": "Result file",
        "ru": "Файл результатов",
        "tr": "Sonuç dosyası",
    },

    # ======================================================================
    # Язык
    # ======================================================================
    "language": {
        "en": "Language",
        "ru": "Язык",
        "tr": "Dil",
    },
    "language_select": {
        "en": "Select interface language",
        "ru": "Выберите язык интерфейса",
        "tr": "Arayüz dilini seçin",
    },

    # ======================================================================
    # CLI
    # ======================================================================
    "cli_description": {
        "en": "CF-Scanner Pro — Cloudflare Edge IP Scanner with Xray-Core Verification",
        "ru": "CF-Scanner Pro — Сканер Cloudflare Edge IP с проверкой через Xray-Core",
        "tr": "CF-Scanner Pro — Xray-Core ile Cloudflare Edge IP Tarayıcı",
    },
    "cli_scan_mode": {
        "en": "Scan mode (default: cloudflare)",
        "ru": "Режим сканирования (по умолчанию: cloudflare)",
        "tr": "Tarama modu (varsayılan: cloudflare)",
    },
    "cli_asn": {
        "en": "ASN to scan (default: AS13335)",
        "ru": "ASN для сканирования (по умолчанию: AS13335)",
        "tr": "Taranacak ASN (varsayılan: AS13335)",
    },
    "cli_cidr": {
        "en": "CIDR/IP to scan (e.g. 188.114.96.0/24)",
        "ru": "CIDR/IP для сканирования (напр. 188.114.96.0/24)",
        "tr": "Taranacak CIDR/IP (örn. 188.114.96.0/24)",
    },
    "cli_ports": {
        "en": "Ports, comma-separated",
        "ru": "Порты через запятую",
        "tr": "Portlar, virgülle ayırın",
    },
    "cli_workers": {
        "en": "Number of TCP workers",
        "ru": "Количество TCP воркеров",
        "tr": "TCP işçi sayısı",
    },
    "cli_deep": {
        "en": "Number of deep verification workers",
        "ru": "Количество воркеров глубокой проверки",
        "tr": "Derin doğrulama işçi sayısı",
    },
    "cli_max": {
        "en": "Max verified results (0 = unlimited)",
        "ru": "Максимум результатов (0 = без ограничений)",
        "tr": "Maksimum sonuç (0 = sınırsız)",
    },
    "cli_xray_path": {
        "en": "Path to Xray-Core binary",
        "ru": "Путь к бинарнику Xray-Core",
        "tr": "Xray-Core ikili dosya yolu",
    },
    "cli_no_xray": {
        "en": "Disable Xray-Core (force raw mode)",
        "ru": "Отключить Xray-Core (принудительно raw режим)",
        "tr": "Xray-Core'u devre dışı bırak (raw modu zorla)",
    },
    "cli_link": {
        "en": "Proxy link (vless://, vmess://, trojan://, ss://)",
        "ru": "Прокси ссылка (vless://, vmess://, trojan://, ss://)",
        "tr": "Proksiy linki (vless://, vmess://, trojan://, ss://)",
    },
    "cli_init_config": {
        "en": "Create config.toml with defaults in current directory",
        "ru": "Создать config.toml с настройками по умолчанию",
        "tr": "Varsayılanlarla config.toml oluştur",
    },
    "cli_show_config": {
        "en": "Show current configuration and exit",
        "ru": "Показать текущую конфигурацию и выйти",
        "tr": "Mevcut yapılandırmayı göster ve çık",
    },
    "cli_lang": {
        "en": "Interface language (en, ru, tr)",
        "ru": "Язык интерфейса (en, ru, tr)",
        "tr": "Arayüz dili (en, ru, tr)",
    },

    # ======================================================================
    # Режимы сканирования (labels)
    # ======================================================================
    "mode_cloudflare": {
        "en": "Cloudflare Detection",
        "ru": "Определение Cloudflare",
        "tr": "Cloudflare Tespiti",
    },
    "mode_raw": {
        "en": "TLS Test (Xray-Core off)",
        "ru": "TLS Тест (Xray-Core выкл)",
        "tr": "TLS Testi (Xray-Core kapalı)",
    },
    "mode_xray": {
        "en": "Xray-Core Full Tunnel (100% accurate)",
        "ru": "Xray-Core Полный туннель (100% точно)",
        "tr": "Xray-Core Tam Tünel (%100 emin)",
    },

    # ======================================================================
    # CLI запуск
    # ======================================================================
    "cli_start_scan": {
        "en": "Starting scan",
        "ru": "Запуск сканирования",
        "tr": "Tarama başlatılıyor",
    },
    "cli_workers_label": {
        "en": "workers",
        "ru": "воркеров",
        "tr": "işçi",
    },

    # ======================================================================
    # Язык (interactive prompt)
    # ======================================================================
    "lang_prompt": {
        "en": "Choose language",
        "ru": "Выберите язык",
        "tr": "Dil seçin",
    },
}


def set_language(lang: str) -> None:
    """Устанавливает текущий язык интерфейса."""
    global _current_lang
    if lang in ("en", "ru", "tr"):
        _current_lang = lang


def get_language() -> str:
    """Возвращает текущий язык."""
    return _current_lang


def t(key: str) -> str:
    """Возвращает перевод по ключу для текущего языка.

    Если ключ не найден, возвращает сам ключ.
    """
    entry = TRANSLATIONS.get(key)
    if entry is None:
        return key
    return entry.get(_current_lang, entry.get("en", key))


def get_available_languages() -> list:
    """Возвращает список доступных языков."""
    return ["en", "ru", "tr"]


def get_language_name(code: str) -> str:
    """Возвращает название языка на самом языке."""
    names = {"en": "English", "ru": "Русский", "tr": "Türkçe"}
    return names.get(code, code)
