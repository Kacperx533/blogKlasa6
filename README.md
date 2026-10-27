# Klasowy Zakątek

Aplikacja blogu klasowego przygotowana do wdrożenia na Vercel. Nie używa adresów e-mail ani plików BAT.

Po uruchomieniu ogłoszenia, kalendarz, materiały, konta uczniów i zaproszenia są puste. Administrator jest tworzony przy pierwszym połączeniu z bazą.

## Aplikacja na telefonie

Stronę można dodać do ekranu telefonu jako aplikację PWA. Na Androidzie otwórz blog w Chrome i wybierz z menu „Zainstaluj aplikację” lub „Dodaj do ekranu głównego”. Na iPhonie otwórz stronę w Safari, stuknij „Udostępnij”, a następnie „Dodaj do ekranu początkowego”. Aplikacja otwiera się osobno, ale do logowania i pobierania danych potrzebuje internetu.

## Wdrożenie na Vercel

1. Wdróż zawartość folderu `outputs` jako katalog główny projektu. Jeśli wdrażasz całe repozytorium, ustaw w Vercel **Root Directory** na `outputs`. W katalogu głównym wdrożenia muszą być obok siebie `index.html`, `package.json` i folder `api/` — bez niego logowanie oraz zapisy nie będą działać.
2. W Vercel połącz projekt z bazą Neon z Marketplace. Integracja dodaje połączenie do projektu jako zmienną `DATABASE_URL`.
3. W ustawieniach projektu → **Environment Variables** dodaj `ADMIN_PASSWORD` i ustaw własne hasło administratora o długości co najmniej 12 znaków. Opcjonalnie ustaw `ADMIN_LOGIN`; domyślny login to `admin`.
4. Wdróż projekt ponownie. Przy pierwszym użyciu aplikacja utworzy puste tabele i konto administratora.

Ekran logowania nie wyświetla loginu administratora ani hasła. Wpisujesz je ręcznie w formularzu. Po zalogowaniu możesz zmienić hasło przyciskiem z kluczem 🔑.

## Funkcje

- logowanie loginem i hasłem, bez e-maila,
- tworzenie kont uczniów i nauczycieli z kodami aktywacyjnymi,
- edycja imienia i loginu utworzonych kont przez administratora,
- usuwanie kont i niewykorzystanych kodów aktywacyjnych przez administratora,
- ogłoszenia, kalendarz i materiały dodawane przez nauczycieli,
- usuwanie ogłoszeń przez administratora lub nauczycieli,
- dodawanie materiałów przez link albo plik (do 2 MB; plik przechowuje się w bazie Neon),
- edycja terminu i usuwanie wydarzeń z kalendarza oraz usuwanie materiałów,
- przełącznik jasnego i ciemnego motywu zapamiętywany w przeglądarce,
- instalacja strony na telefonie jako aplikacji PWA,
- widok uczniów i nauczycieli klasy,
- wspólna baza danych dla osób korzystających z wdrożonej strony.

Konta, hasła i treści zapisują się w bazie Neon; pliki systemowe Vercel nie są używane do przechowywania danych. Nie dodawaj haseł ani adresów bazy do kodu aplikacji.
