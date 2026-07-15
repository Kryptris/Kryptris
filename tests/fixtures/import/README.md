# Import-Fixtures

Die Dateien bilden die nativen Klartext-Exportstrukturen der unterstützten Hersteller ab; sämtliche Inhalte und Geheimnisse sind erfunden.

- `1password.csv`: `Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`
- `lastpass.csv`: `url,username,password,extra,name,grouping,fav`
- `keepass.csv`: `Group,Title,Username,Password,URL,Notes`
- `chrome.csv`: `name,url,username,password,note`
- `edge.csv`: `name,url,username,password`
- `firefox.csv`: `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged`
- `bitwarden.json`: unverschlüsselter JSON-Export mit `folders`, `items`, `login` und `fields`
- `proton-pass.json`: JSON-Export mit `vaults`, `items`, `data.metadata`, `data.content` und `data.extraFields`

Generisches CSV und JSON werden separat mit expliziter Feldzuordnung getestet, weil sie bewusst keinem Herstellerformat folgen.
