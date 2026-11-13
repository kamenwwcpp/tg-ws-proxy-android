<div align="center">

# Telegram WS Proxy для Android

**Локальный MTProto-прокси, который помогает Telegram работать в сетях с блокировками —
на Wi-Fi и на мобильном интернете.**

<br>

<a href="https://github.com/kamenwwcpp/tg-ws-proxy-android/releases/latest"><img src="https://img.shields.io/github/v/release/kamenwwcpp/tg-ws-proxy-android?style=for-the-badge&label=%D0%A1%D0%BA%D0%B0%D1%87%D0%B0%D1%82%D1%8C&color=2ea44f" alt="Скачать"></a>
<img src="https://img.shields.io/badge/Android-5.0%2B-3DDC84?style=for-the-badge&logo=android&logoColor=white" alt="Android 5.0+">
<img src="https://img.shields.io/badge/%D1%8F%D0%B4%D1%80%D0%BE-Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go">
<a href="https://github.com/kamenwwcpp/tg-ws-proxy-android/stargazers"><img src="https://img.shields.io/github/stars/kamenwwcpp/tg-ws-proxy-android?style=for-the-badge&logo=github&color=ffca28&labelColor=24292e" alt="Stars"></a>

</div>

<br>

<img width="972" height="696" alt="Скриншоты приложения" src="https://github.com/user-attachments/assets/7c9b9f2a-fc60-4aee-b93d-db950e24555c" />

## Что это

Приложение поднимает на телефоне прокси `127.0.0.1:1443`, к которому подключается Telegram. Дальше прокси сам ищет рабочий путь до серверов Telegram: через WebSocket напрямую или через Cloudflare — и запоминает, что работает именно в твоей сети.

- **Не VPN.** Трафик других приложений не трогается, VPN-слот остаётся свободным — можно одновременно пользоваться любым VPN.
- **Не нужен свой сервер или подписка.** Прокси работает на самом телефоне, сообщения Telegram остаются зашифрованы как обычно.
- **Бережёт батарею.** Без постоянного wake lock, фоновая работа только по делу.

> [!NOTE]
> Это продолжение Android-версии **[amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android)**, основанной на **[Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)**. История коммитов сохранена. Здесь — упор на стабильность в сетях РФ, мобильный интернет и расход батареи; часть идей взята из форков [crim50n](https://github.com/crim50n/tg-ws-proxy-android) и [Alexingin](https://github.com/Alexingin/tg-ws-proxy-android).

## Установка

Скачай APK со **[страницы последнего релиза](https://github.com/kamenwwcpp/tg-ws-proxy-android/releases/latest)**:

| Файл | Для кого |
|---|---|
| `TgWsProxy-…-arm64.apk` | почти все телефоны последних лет (Android 7.0+) |
| `TgWsProxy-…-universal.apk` | если не уверен, какой выбрать (Android 5.0+) |
| `TgWsProxy-…-arm32.apk` | старые 32-битные устройства (Android 5.0+) |

> [!WARNING]
> Начиная с **1.3.2** у приложения новая подпись. Если стоит версия **1.3.1 или старше** (или версия от amurcanov) — сначала удали её, иначе Android не даст установить поверх. После этого прокси в Telegram нужно добавить заново (см. ниже).

## Быстрый старт

1. Открой приложение и нажми большую круглую кнопку — статус сменится на **«Подключено»**, появится уведомление о работе в фоне.
2. Нажми **«Применить в Telegram»** — откроется Telegram, подтверди добавление прокси.
3. Готово. Прокси работает в фоне, пока его не выключишь.

> [!TIP]
> В Telegram должна быть **одна** запись прокси `127.0.0.1:1443`. Если остались старые (например, после переустановки приложения), удали их в *Настройки → Данные и память → Прокси*: со старым секретом Telegram будет без конца долбиться в прокси и мешать нормальной работе.

Поддерживаются официальный Telegram и большинство форков: exteraGram, AyuGram, Nekogram, Plus Messenger, Telegram X и другие.

## Как это работает

Telegram подключается к локальному MTProto-прокси. Go-ядро выбирает WebSocket-маршрут до нужного дата-центра Telegram и пробует до трёх подключений одновременно. На мобильной сети может первым проверяться Cloudflare. Рабочий маршрут запоминается отдельно для типа сети, дата-центра и медиа.

После смены сети ядро закрывает старые соединения и очищает пул WebSocket. Пока Android сообщает об отсутствии сети, прокси не запускает новых подключений. Настройки портов и адресов дата-центров, секрет Telegram, автоподъём и статистику обслуживает прежнее Android-приложение.

Go-ядро взято из [keelbismark](https://github.com/keelbismark/tg-ws-proxy-android/commit/f7d850f2ea1d4e406e812323e7f81f1f34bd50e6) с правками [VintlGvard](https://github.com/VintlGvard/tg-ws-proxy-android/commit/9b8e96bd57ae8661fabfd8f084fadb86d4c46056). Условия использования ядра указаны в [core/LICENSE](core/LICENSE).


## Если что-то не работает

<details>
<summary><b>Telegram пишет «Подключённый Вами прокси-сервер использует некорректные настройки»</b></summary>

Telegram сам отключает прокси, когда сервер Telegram отвечает ошибкой «не тот дата-центр». Проверь, что в Telegram одна запись прокси с актуальным секретом (кнопка «Применить в Telegram»), и снова включи прокси в настройках Telegram. Точная причина не выяснена ни здесь, ни в оригинальном tg-ws-proxy. С 1.3.4 обычные соединения идут только на основной домен дата-центра, как в оригинале, — возможно, это помогает.
</details>

<details>
<summary><b>На Wi-Fi всё отлично, на мобильном интернете медленно</b></summary>

У многих операторов прямой путь к Telegram заблокирован, и трафик идёт через Cloudflare — он медленнее, а медиа на нём иногда подрезается. Прокси сам переключается на этот маршрут после первой неудачи. Первые секунды после запуска прокси уходят на то, чтобы это выяснить, дальше подключения идут сразу правильным путём.
</details>

<details>
<summary><b>При «белых списках» у оператора ничего не работает</b></summary>

В этом режиме оператор пропускает только разрешённые адреса, а адресов Telegram и Cloudflare в списке нет. Обойти это локальный прокси не может — нужен сервер-посредник на разрешённом адресе.
</details>

<details>
<summary><b>Прокси пропадает в фоне</b></summary>

Некоторые прошивки (Xiaomi, Huawei, OnePlus, Samsung) агрессивно выгружают фоновые приложения. Разреши приложению работу в фоне без ограничений в настройках батареи и закрепи его в списке недавних. Включи **«Автозапуск»** в настройках приложения, чтобы прокси поднимался после перезагрузки.
</details>

<details>
<summary><b>Как сообщить об ошибке</b></summary>

Нажми **«Собрать отчёт»** в приложении и приложи его к [issue](https://github.com/kamenwwcpp/tg-ws-proxy-android/issues). Укажи сеть (Wi-Fi или мобильная, оператор) и что именно не работает: сообщения, медиа, звонки. Единичные ошибки в логах при нормально работающем прокси — это нормально.
</details>

## Видеогайд

Гайд снят для оригинальной Android-версии, но установка и настройка не изменились.

<div align="center">

<img width="1376" height="768" alt="Видеогайд" src="https://github.com/user-attachments/assets/ed1449d4-0a14-4b46-8f35-b787bdee3e32" />

[**Смотреть на YouTube**](https://youtu.be/RP4RwyEHpwc) · [**Смотреть в Telegram**](https://t.me/avencoreschat/506796)

</div>

## Сборка из исходников

Нужны **Go** (1.25.4+), **Android SDK** с **NDK**, **JDK 17+**. Скрипты рассчитаны на Windows.

```bat
:: 1. Нативное ядро для arm64-v8a и armeabi-v7a -> app/src/main/jniLibs
powershell -ExecutionPolicy Bypass -File .\build_go.ps1

:: 2. APK (universal, arm64, arm32) -> app/build/outputs/apk
gradlew.bat assembleRelease
```

Для подписанного релиза положи keystore в корень проекта и добавь в `local.properties`:

```properties
sdk.dir=C\:\\путь\\к\\android-sdk
KEYSTORE_FILE=../release.keystore
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

Без этого Gradle подпишет сборку отладочным ключом. `release.keystore` и `local.properties` в репозиторий не попадают — храни их копию отдельно, иначе следующую версию не получится поставить поверх.

## Благодарности и лицензия

- **[Flowseal](https://github.com/Flowseal)** — оригинальный [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) (MIT).
- **[amurcanov](https://github.com/amurcanov)** — Android-версия, на которой основан этот проект (GPLv3).
- **[crim50n](https://github.com/crim50n/tg-ws-proxy-android)** и **[Alexingin](https://github.com/Alexingin/tg-ws-proxy-android)** — идеи по маршрутизации и самовосстановлению.

Проект распространяется под лицензией **GPLv3**.
