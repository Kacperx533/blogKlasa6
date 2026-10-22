# Klasowy Zakątek

Aplikacja blogu klasowego przygotowana do wdrożenia na Vercel. Nie używa adresów e-mail ani plików BAT.

Po uruchomieniu ogłoszenia, kalendarz, materiały, konta uczniów i zaproszenia są puste. Administrator jest tworzony przy pierwszym połączeniu z bazą.

## Wdrożenie na Vercel

1. Dodaj zawartość folderu `outputs` do projektu, który wdrażasz na Vercel.
2. W Vercel połącz projekt z bazą Neon z Marketplace. Integracja dodaje połączenie do projektu jako zmienną `DATABASE_URL`.
3. W ustawieniach projektu → **Environment Variables** dodaj `ADMIN_PASSWORD` i ustaw własne hasło administratora o długości co najmniej 12 znaków. Opcjonalnie ustaw `ADMIN_LOGIN`; domyślny login to `admin`.
4. Wdróż projekt ponownie. Przy pierwszym użyciu aplikacja utworzy puste tabele i konto administratora.

Ekran logowania nie wyświetla loginu administratora ani hasła. Wpisujesz je ręcznie w formularzu. Po zalogowaniu możesz zmienić hasło przyciskiem z kluczem 🔑.

## Funkcje

- logowanie loginem i hasłem, bez e-maila,
- tworzenie kont uczniów i nauczycieli z kodami aktywacyjnymi,
- ogłoszenia, kalendarz i materiały dodawane przez nauczycieli,
- widok uczniów i nauczycieli klasy,
- wspólna baza danych dla osób korzystających z wdrożonej strony.

Konta, hasła i treści zapisują się w bazie Neon; pliki systemowe Vercel nie są używane do przechowywania danych. Nie dodawaj haseł ani adresów bazy do kodu aplikacji.
