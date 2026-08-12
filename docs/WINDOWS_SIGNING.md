# Signature Windows et SmartScreen

Microsoft Defender SmartScreen affiche `Unknown publisher` lorsqu'un exécutable Windows n'est pas signé avec un certificat de signature de code reconnu, ou lorsqu'il n'a pas encore assez de réputation.

Ce message ne signifie pas automatiquement que NetScope Scanner est malveillant. Il indique surtout que Windows ne peut pas vérifier l'identité de l'éditeur.

## Solution de production

Pour une distribution professionnelle, signez les releases avec un certificat de signature de code :

- OV Code Signing : éditeur vérifié, la réputation SmartScreen se construit avec le temps.
- EV Code Signing : validation plus forte, réputation généralement plus rapide, mais coût et contraintes plus élevés.

Le certificat doit être acheté auprès d'une autorité de certification reconnue. Ne commitez jamais le certificat, le `.pfx`, le mot de passe ou une clé privée dans Git.

## GitHub Actions

Le workflow `.github/workflows/release.yml` sait signer automatiquement l'exécutable si ces secrets GitHub existent :

- `WINDOWS_CODESIGN_PFX_B64` : contenu du certificat `.pfx` encodé en Base64.
- `WINDOWS_CODESIGN_PASSWORD` : mot de passe du certificat.

Pour générer la valeur Base64 depuis Windows :

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\chemin\certificat.pfx")) | Set-Clipboard
```

Ensuite, ajoutez la valeur copiée dans GitHub :

`Repository Settings -> Secrets and variables -> Actions -> New repository secret`

## Build local signé

Après un build PyInstaller local :

```powershell
signtool sign /f "C:\chemin\certificat.pfx" /p "MOT_DE_PASSE" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 "dist\NetScope Scanner.exe"
```

## Avant la signature

Un utilisateur peut lancer l'application avec :

`More info -> Run anyway`

Ce contournement est acceptable uniquement pour vos tests internes ou une distribution contrôlée. Pour publier largement, signez l'exécutable.
