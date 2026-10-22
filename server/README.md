# RBX Manager — Backend + licence

Serveur FastAPI (auth, licences, sessions) et client C# (WinForms).

## Structure

```
server/
  app/
    main.py       routes REST
    models.py     tables users / licenses / sessions
    schemas.py    contrats pydantic
    security.py   bcrypt, tokens, génération de clés
    db.py         SQLAlchemy (SQLite ou PostgreSQL)
    config.py     variables d'environnement
  requirements.txt
  run.bat         install venv + lance uvicorn (port 8000)
  test_api.py     test de bout en bout (TestClient)
  .env.example

LicenseClient.cs   client HTTP (API + admin)
AuthCore.cs        HWID, cache AES-256/PBKDF2, reprise de session
AuthForm.cs        fenêtre LOGIN / REGISTER
KeyGen.cs          RBXKeyGen.exe (outil admin)
RobloxManager.cs   application principale (features existantes intactes)
build.bat          compile RBXManager.exe + RBXKeyGen.exe
```

## Lancer le serveur

```bat
cd server
run.bat
```

`run.bat` crée `.venv`, installe les dépendances, copie `.env.example` vers `.env`
puis lance `http://127.0.0.1:8000`.

Production (Supabase / PostgreSQL) : renseigne `DATABASE_URL` dans `server/.env` :

```
DATABASE_URL=postgresql+psycopg2://postgres:MOTDEPASSE@db.xxxx.supabase.co:5432/postgres
ADMIN_SECRET=un-secret-long-et-aleatoire
```

Les tables sont créées automatiquement au démarrage.

## Générer une clé

```bat
curl -X POST http://127.0.0.1:8000/admin/generate-keys ^
  -H "Content-Type: application/json" ^
  -H "X-Admin-Secret: change-me-please" ^
  -d "{\"count\":5,\"duration_days\":30}"
```

Ou avec l'outil graphique `RBXKeyGen.exe` (mot de passe = `ADMIN_SECRET`).

Formats : `duration_days` = 7 / 30 / 365, ou `-1` pour lifetime.

## Client

`build.bat` produit :

- `RBXManager.exe` — application, protégée par login + licence
- `RBXKeyGen.exe` — générateur de clés admin

Adresse du serveur : `%AppData%\RBXManager\config.ini`

```ini
api_base=http://127.0.0.1:8000
```

Pour une prod : `api_base=https://api.ton-domaine.com`.

## Flux de lancement

1. HWID = SHA-256(ProcessorId + SerialNumber carte mère), base64.
2. Si `%AppData%\RBXManager\session.dat` existe, non expiré et déchiffrable
   (AES-256-CBC + HMAC-SHA256, clé PBKDF2 dérivée du HWID) :
   `POST /license/validate` silencieux → MainWindow.
3. Sinon AuthWindow : LOGIN (username/password → licence liée au compte)
   ou REGISTER (username/password/clé → register + login + activate).
4. Logout : suppression du cache + `POST /auth/logout` + retour à AuthWindow.

## Endpoints

| Méthode | Route | Auth |
| --- | --- | --- |
| POST | `/auth/register` | — |
| GET | `/auth/check-username?username=` | — |
| POST | `/auth/login` | — |
| POST | `/auth/logout` | Bearer |
| POST | `/license/activate` | Bearer |
| POST | `/license/validate` | — |
| GET | `/license/mine` | Bearer |
| POST | `/admin/generate-keys` | X-Admin-Secret |
| GET | `/admin/keys` | X-Admin-Secret |
| DELETE | `/admin/revoke/{key}` | X-Admin-Secret |

`/license/mine` et `/auth/check-username` sont des ajouts nécessaires au client
(le login ne demande que username/password, il faut retrouver la clé liée).

## Sécurité

- bcrypt coût 12, jamais de mot de passe en clair.
- Token de session : `secrets.token_urlsafe(32)`, 30 jours, supprimé au logout.
- HWID lié à la première activation ; toute autre machine reçoit 403.
- Une clé déjà liée à un compte ne peut pas être réclamée par un autre.
- Cache local chiffré AES-256-CBC + HMAC, clé PBKDF2 (100 000 itérations).
- Toutes les requêtes client ont un timeout de 10 s.

## Tests

```bat
cd server
.venv\Scripts\pip install httpx
.venv\Scripts\python test_api.py
```

Le test utilise une base SQLite temporaire : il ne touche pas `rbxmanager.db`.

## Notes

- L'app existante est en **WinForms** (pas WPF) : les nouvelles fenêtres
  respectent le même thème sombre et les mêmes composants.
- Le créateur automatique de comptes Roblox (UI, workers, proxies, captcha,
  fichiers `RBXAutoCreator.cs` / `RBXProxyHunter.cs` / `ProxyListDialog.cs`)
  a été supprimé. Les comptes, cookies, multi-launch, Place ID et l'import
  de cookies sont inchangés.
