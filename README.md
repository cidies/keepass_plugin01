# KeePass Record Exchange Plugin

`keepass_plugin01` erweitert KeePass 2.x um einen verschlüsselten Austausch vollständiger Einträge zwischen KeePass-Instanzen. Ein oder mehrere markierte Einträge können über die Windows-Zwischenablage oder über eine verschlüsselte `.kprx`-Datei exportiert und anschließend in eine andere geöffnete KeePass-Datenbank importiert werden.

Das Plugin überträgt:

- alle Standardfelder wie Titel, Benutzername, Passwort, URL und Notizen,
- benutzerdefinierte Felder,
- den Schutzstatus der Felder,
- Tags,
- Ablaufstatus und Ablaufzeit,
- das Standard-Icon,
- Dateianhänge.

UUID, Erstellungs- und Änderungszeitpunkte sowie die Änderungshistorie werden nicht übernommen. Beim Import wird bewusst ein neuer KeePass-Eintrag erzeugt.

## Funktionen

Das Plugin stellt unter **Extras → Record Exchange** und im Kontextmenü eines Eintrags folgende Befehle bereit:

| Befehl | Funktion |
|---|---|
| `COPY RECORD ENCRYPTED` | Verschlüsselt die markierten Einträge und legt den verschlüsselten Container in der Windows-Zwischenablage ab. |
| `PASTE RECORD ENCRYPTED` | Liest und entschlüsselt einen Container aus der Zwischenablage und legt daraus neue Einträge an. |
| `EXPORT RECORD TO FILE` | Exportiert die markierten Einträge als verschlüsselte `.kprx`-Datei. |
| `IMPORT RECORD FROM FILE` | Entschlüsselt eine `.kprx`-Datei und importiert die darin enthaltenen Einträge. |

Mehrere Einträge können in KeePass mit `Strg` oder `Umschalt` gemeinsam markiert und in einem Vorgang übertragen werden.

## Sicherheitskonzept

Die eigentlichen KeePass-Datensätze werden vor der Ablage in der Zwischenablage oder in einer Datei vollständig verschlüsselt. Sichtbar bleiben ausschließlich die technischen Parameter, die zur Ableitung des Schlüssels und zur Entschlüsselung benötigt werden.

Verwendete Verfahren:

- Schlüsselableitung: PBKDF2-HMAC-SHA-256
- Iterationen: 600.000
- Salt: 16 zufällige Byte pro Export
- Verschlüsselung: AES-256-GCM
- Nonce: 12 zufällige Byte pro Export
- Authentifizierungs-Tag: 128 Bit
- zusätzliche authentifizierte Daten: Format- und Versionskennung

AES-GCM stellt sowohl Vertraulichkeit als auch Integrität bereit. Ein falsches Passwort und eine manipulierte Exportdatei führen absichtlich zur gleichen Fehlermeldung.

### Transferpasswort

Das Transferpasswort:

- wird beim Kopieren oder Datei-Export zweimal abgefragt,
- muss mindestens zwölf Zeichen lang sein,
- wird nicht in der Exportdatei gespeichert,
- wird nicht als Hash gespeichert,
- sollte nicht mit dem Masterpasswort der KeePass-Datenbank identisch sein.

Empfohlen wird eine eigenständige, lange Passphrase, zum Beispiel nach folgendem Muster:

```text
Segelboot-Kupfer-Atlas-Donau-47
```

Die Verschlüsselung kann ein schwaches Transferpasswort nicht kompensieren. Eine gespeicherte `.kprx`-Datei erlaubt grundsätzlich einen Offline-Angriff auf das Transferpasswort.

### Schutz der Zwischenablage

Bei `COPY RECORD ENCRYPTED` liegt ausschließlich der verschlüsselte Container in der Zwischenablage. Das Plugin kennzeichnet den Inhalt zusätzlich mit den von Windows vorgesehenen Formaten:

```text
ExcludeClipboardContentFromMonitorProcessing
CanIncludeInClipboardHistory = 0
CanUploadToCloudClipboard = 0
```

Dadurch soll Windows den Inhalt weder in die Zwischenablagehistorie aufnehmen noch über das Cloud Clipboard synchronisieren.

Der Inhalt wird außerdem:

- nach 30 Sekunden automatisch gelöscht,
- nach einem erfolgreichen Import sofort gelöscht,
- beim Beenden des Plugins gelöscht.

Das Plugin löscht die Zwischenablage nur, wenn sie noch genau den zuvor vom Plugin geschriebenen Inhalt enthält. Ein Text, den der Benutzer zwischenzeitlich kopiert hat, wird nicht gelöscht.

Diese Maßnahmen können nicht garantieren, dass Schadsoftware oder ein fremder Clipboard-Manager den Inhalt nicht vorher ausliest. Aufgrund der Verschlüsselung erhält ein solcher Prozess jedoch nicht unmittelbar die Kennwörter und übrigen Datensatzinhalte.

## Voraussetzungen für die Entwicklung

### Software

- Windows 10 oder Windows 11
- KeePass 2.x, vorzugsweise die aktuelle offizielle Version
- Visual Studio mit der Workload **.NET-Desktopentwicklung**
- .NET Framework 4.8 Developer Pack
- NuGet-Paketverwaltung

Das Projekt muss als folgende Vorlage angelegt werden:

```text
C# → Klassenbibliothek (.NET Framework)
```

Zielframework:

```text
.NET Framework 4.8
```

Nicht geeignet sind `.NET Standard`, `.NET Core`, .NET 6 oder andere moderne .NET-Klassenbibliotheken, da KeePass 2.x das Plugin als .NET-Framework-Assembly lädt.

## Erforderliche Assembly-Verweise

Das Projekt benötigt folgende Verweise:

| Assembly | Herkunft | Einstellung |
|---|---|---|
| `KeePass` | Verweis auf eine offizielle `KeePass.exe` | `Lokale Kopie = False` |
| `System` | .NET Framework | Standard |
| `System.Drawing` | .NET Framework | Standard |
| `System.Web.Extensions` | .NET Framework | Standard |
| `System.Windows.Forms` | .NET Framework | Standard |
| `BouncyCastle.Cryptography` | NuGet | `Lokale Kopie = True` |

### KeePass-Verweis hinzufügen

1. Im Projektmappen-Explorer mit der rechten Maustaste auf **Verweise** klicken.
2. **Verweis hinzufügen → Durchsuchen** auswählen.
3. Eine offizielle `KeePass.exe` auswählen, beispielsweise:

   ```text
   D:\Program Files\KeePass Password Safe 2\KeePass.exe
   ```

4. Den neuen Verweis `KeePass` markieren.
5. Im Eigenschaftenfenster `Lokale Kopie` auf `False` setzen.

Es sollte möglichst dieselbe KeePass-Version referenziert werden, mit der das Plugin später getestet wird. Die offizielle portable KeePass-Version eignet sich ebenfalls als Referenz.

### Framework-Verweise hinzufügen

Unter **Verweise → Verweis hinzufügen → Assemblys → Framework** müssen folgende Assemblys aktiviert werden:

```text
System.Drawing
System.Web.Extensions
System.Windows.Forms
```

### BouncyCastle installieren

In Visual Studio die Paket-Manager-Konsole öffnen:

```text
Extras → NuGet-Paket-Manager → Paket-Manager-Konsole
```

Danach ausführen:

```powershell
Install-Package BouncyCastle.Cryptography -Version 2.7.0
```

Unter **Verweise** muss anschließend `BouncyCastle.Cryptography` erscheinen. Für diesen Verweis muss gelten:

```text
Lokale Kopie = True
```

Beim Build muss dadurch neben der Plugin-DLL auch folgende Datei im Ausgabeverzeichnis entstehen:

```text
BouncyCastle.Cryptography.dll
```

## Namenskonventionen von KeePass

KeePass erwartet eine feste Beziehung zwischen Dateiname, Namespace und Hauptklasse:

| Element | Wert dieses Projekts |
|---|---|
| Plugin-DLL | `keepass_plugin01.dll` |
| Namespace | `keepass_plugin01` |
| Hauptklasse | `keepass_plugin01Ext` |

Die Klassendefinition lautet deshalb:

```csharp
namespace keepass_plugin01
{
    public sealed class keepass_plugin01Ext : Plugin
    {
        // Plugin-Code
    }
}
```

Wenn das Projekt oder die DLL umbenannt wird, müssen Namespace und Klassenname entsprechend angepasst werden.

## Assembly-Informationen

KeePass erkennt eine DLL anhand ihrer Assembly-Metadaten als Plugin. In `Properties\AssemblyInfo.cs` muss der Produktname exakt `KeePass Plugin` lauten:

```csharp
[assembly: AssemblyTitle("KeePass Record Exchange")]
[assembly: AssemblyDescription("Encrypted exchange of KeePass records")]
[assembly: AssemblyCompany("Zentric")]
[assembly: AssemblyProduct("KeePass Plugin")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
```

Entscheidend ist:

```csharp
[assembly: AssemblyProduct("KeePass Plugin")]
```

Ohne diesen Wert wird die DLL von KeePass nicht als Plugin erkannt.

## Projektaufbau

Ein minimaler Projektaufbau sieht so aus:

```text
keepass_plugin01
├── Properties
│   └── AssemblyInfo.cs
├── keepass_plugin01Ext.cs
├── packages.config
└── keepass_plugin01.csproj
```

Je nach NuGet-Konfiguration kann anstelle von `packages.config` ein `PackageReference` im Projekt verwendet werden.

## Kompilieren

1. KeePass vollständig schließen.
2. In Visual Studio oben `Debug` oder für eine Veröffentlichung `Release` auswählen.
3. **Erstellen → Projektmappe neu erstellen** auswählen.
4. Die Fehlerliste kontrollieren.

Das Build-Ergebnis befindet sich normalerweise unter:

```text
bin\Debug\
```

oder:

```text
bin\Release\
```

Mindestens folgende Dateien müssen vorhanden sein:

```text
keepass_plugin01.dll
BouncyCastle.Cryptography.dll
```

Eine Klassenbibliothek kann nicht direkt über den normalen Startknopf ausgeführt werden. Die Meldung, dass ein Projekt mit dem Ausgabetyp „Klassenbibliothek“ nicht direkt gestartet werden kann, ist daher normal.

## Installation

1. KeePass vollständig beenden.
2. In KeePass **Extras → Plugins → Open Folder** verwenden, um den tatsächlich verwendeten Plugin-Ordner zu ermitteln.
3. Folgende Dateien aus `bin\Debug` oder `bin\Release` direkt in diesen Ordner kopieren:

   ```text
   keepass_plugin01.dll
   BouncyCastle.Cryptography.dll
   ```

Beispiel:

```text
D:\Program Files\KeePass Password Safe 2\Plugins\
```

Der Ordner sollte anschließend unter anderem enthalten:

```text
Plugins
├── keepass_plugin01.dll
└── BouncyCastle.Cryptography.dll
```

4. KeePass neu starten.
5. Unter **Extras → Plugins** prüfen, ob das Plugin aufgeführt wird.

Bei jedem neuen Build muss mindestens `keepass_plugin01.dll` erneut in den Plugin-Ordner kopiert werden. Wenn die BouncyCastle-Version geändert wurde, muss auch `BouncyCastle.Cryptography.dll` ersetzt werden.

## Benutzung

### Einträge über die Zwischenablage übertragen

#### Kopieren

1. Die gewünschten Einträge in KeePass auswählen.
2. Für mehrere Einträge `Strg` oder `Umschalt` verwenden.
3. Mit der rechten Maustaste auf die Auswahl klicken oder das Menü **Extras** öffnen.
4. **Record Exchange → COPY RECORD ENCRYPTED** auswählen.
5. Ein Transferpasswort mit mindestens zwölf Zeichen eingeben.
6. Das Passwort ein zweites Mal bestätigen.

Der verschlüsselte Container befindet sich anschließend für maximal 30 Sekunden in der Zwischenablage.

#### Einfügen

1. Zur KeePass-Instanz und Datenbank wechseln, in die importiert werden soll.
2. In der gewünschten Zielgruppe einen vorhandenen Eintrag auswählen. Der Import erfolgt dann in derselben Gruppe.
3. Alternativ nur die gewünschte Gruppe auswählen.
4. **Record Exchange → PASTE RECORD ENCRYPTED** auswählen.
5. Das beim Kopieren festgelegte Transferpasswort eingeben.

Nach erfolgreichem Import wird der verschlüsselte Container sofort aus der Zwischenablage entfernt.

### Einträge als Datei exportieren

1. Einen oder mehrere Einträge markieren.
2. **Record Exchange → EXPORT RECORD TO FILE** auswählen.
3. Transferpasswort eingeben und bestätigen.
4. Speicherort und Dateinamen auswählen.

Das Plugin verwendet standardmäßig die Dateiendung:

```text
.kprx
```

Die Exportdatei enthält keine Datensatzfelder im Klartext.

### Einträge aus einer Datei importieren

1. Zielgruppe oder einen Eintrag innerhalb der Zielgruppe auswählen.
2. **Record Exchange → IMPORT RECORD FROM FILE** auswählen.
3. Die gewünschte `.kprx`-Datei auswählen.
4. Das beim Export verwendete Transferpasswort eingeben.

Die Exportdatei wird nach dem Import nicht automatisch gelöscht. Sie kann erneut verwendet werden, solange das Transferpasswort bekannt ist.

## Auswahl der Zielgruppe

Das Plugin bestimmt die Importgruppe nach folgender Reihenfolge:

1. Ist ein Eintrag ausgewählt, wird dessen übergeordnete Gruppe verwendet.
2. Andernfalls wird die aktuell ausgewählte KeePass-Gruppe verwendet.
3. Falls keine Gruppe bestimmt werden kann, wird die Stammgruppe der geöffneten Datenbank verwendet.

## Behandlung vorhandener Titel

Vor jedem Import prüft das Plugin innerhalb der Zielgruppe, ob dort bereits ein Eintrag mit demselben Titel existiert. Die Prüfung ignoriert Groß- und Kleinschreibung.

Bei einer Kollision wird `_copy` angehängt:

```text
Server
Server_copy
Server_copy_copy
```

Der vorhandene Eintrag wird nicht verändert oder überschrieben.

## Containerformat

Die Zwischenablage und `.kprx`-Dateien verwenden dasselbe JSON-basierte Containerformat. Der äußere Container sieht prinzipiell so aus:

```json
{
  "Format": "KeePassRecordExchange",
  "Version": 1,
  "Kdf": "PBKDF2-HMAC-SHA256",
  "Iterations": 600000,
  "Salt": "BASE64",
  "Cipher": "AES-256-GCM",
  "Nonce": "BASE64",
  "Ciphertext": "BASE64"
}
```

Der GCM-Authentifizierungs-Tag ist Bestandteil des Base64-kodierten Feldes `Ciphertext`. Der entschlüsselte Inhalt besteht aus einer JSON-Liste mit einem oder mehreren KeePass-Datensätzen.

Die Felder außerhalb von `Ciphertext` enthalten keine Titel, Benutzernamen, Passwörter, Notizen oder Anhänge.

## Begrenzungen

Zur Reduzierung von Ressourcenmissbrauch gelten folgende Grenzen:

- maximal 10.000 Datensätze pro Container,
- maximal ungefähr 100 MB Dateigröße,
- begrenzte JSON-Rekursionstiefe,
- PBKDF2-Iterationswerte beim Import zwischen 100.000 und 5.000.000.

Sehr große Anhänge vergrößern den Container durch Base64-Kodierung deutlich. Für große Dateiübertragungen ist die Zwischenablage daher weniger geeignet als der `.kprx`-Export.

## Fehlerbehebung

### Plugin erscheint nicht in KeePass

Prüfen:

1. Liegt `keepass_plugin01.dll` im tatsächlich von KeePass verwendeten Plugin-Ordner?
2. Wurde KeePass nach dem Kopieren vollständig neu gestartet?
3. Lautet der Produktname in `AssemblyInfo.cs` exakt `KeePass Plugin`?
4. Stimmen DLL-Name, Namespace und Klassenname überein?

```text
keepass_plugin01.dll
namespace keepass_plugin01
class keepass_plugin01Ext
```

### BouncyCastle.Cryptography wurde nicht gefunden

Typische Meldung:

```text
Die Datei oder Assembly "BouncyCastle.Cryptography" oder eine Abhängigkeit davon wurde nicht gefunden.
```

Lösung:

1. Prüfen, ob `BouncyCastle.Cryptography.dll` unter `bin\Debug` beziehungsweise `bin\Release` erzeugt wurde.
2. Beim BouncyCastle-Verweis `Lokale Kopie = True` setzen.
3. `BouncyCastle.Cryptography.dll` direkt neben `keepass_plugin01.dll` in den KeePass-Plugin-Ordner kopieren.
4. Keine beliebige Version aus dem Internet verwenden, sondern genau die DLL aus dem Ausgabeordner desselben Builds.

### `System.Web.Script` oder `JavaScriptSerializer` wurde nicht gefunden

Der Verweis `System.Web.Extensions` fehlt.

```text
Verweise → Verweis hinzufügen → Assemblys → Framework → System.Web.Extensions
```

### `ToolStripMenuItem` oder `MessageBox` wurde nicht gefunden

Der Verweis `System.Windows.Forms` fehlt.

```text
Verweise → Verweis hinzufügen → Assemblys → Framework → System.Windows.Forms
```

### Der Typ `Image` befindet sich in einer nicht referenzierten Assembly

Der Verweis `System.Drawing` fehlt.

```text
Verweise → Verweis hinzufügen → Assemblys → Framework → System.Drawing
```

### Projekt kann nicht direkt gestartet werden

Das ist bei einer Klassenbibliothek normal. Zum Debuggen kann in den Projekteigenschaften unter **Debuggen** die KeePass-EXE als externes Programm eingetragen werden:

```text
D:\Program Files\KeePass Password Safe 2\KeePass.exe
```

Die Plugin-DLL muss trotzdem im Plugin-Ordner liegen.

### Falsches Passwort oder Container verändert

Aus Sicherheitsgründen verwendet das Plugin für beide Fälle dieselbe Meldung:

```text
Das Passwort ist falsch oder der Container wurde verändert.
```

Prüfen:

- Wurde exakt dasselbe Transferpasswort verwendet?
- Wurde der Zwischenablageinhalt unvollständig kopiert?
- Wurde die `.kprx`-Datei verändert oder beschädigt?
- Stammen Export und Import aus kompatiblen Containerformat-Versionen?

## Aktualisierung des Plugins

1. KeePass schließen.
2. Neue Version kompilieren.
3. Alte `keepass_plugin01.dll` im Plugin-Ordner ersetzen.
4. Bei einer geänderten NuGet-Version auch `BouncyCastle.Cryptography.dll` ersetzen.
5. KeePass neu starten und unter **Extras → Plugins** die geladene Version prüfen.

Für veröffentlichte Versionen sollten `AssemblyVersion` und `AssemblyFileVersion` in `AssemblyInfo.cs` nachvollziehbar erhöht werden.

## Sicherheitsgrenzen

Das Plugin schützt exportierte Daten im Ruhezustand und während der Übertragung über Datei oder Zwischenablage. Es schützt nicht gegen:

- Schadsoftware mit Zugriff auf den KeePass-Prozess,
- Keylogger bei der Eingabe des Transferpassworts,
- Speicherabbilder des laufenden Prozesses,
- ein schwaches oder bereits kompromittiertes Transferpasswort,
- manipulierte Plugin- oder KeePass-Binärdateien,
- einen bereits vollständig kompromittierten Windows-Benutzerkontext.

Während des Exports muss das Plugin die geschützten KeePass-Felder kurzzeitig entschlüsseln, serialisieren und im Prozessspeicher verarbeiten. Die verwendeten Byte-Arrays werden soweit möglich überschrieben. Zeichenketten in .NET sind unveränderlich und können nicht zuverlässig unmittelbar aus dem Managed Heap gelöscht werden.

## Empfehlungen für den produktiven Einsatz

- Nur offizielle KeePass-Versionen als Referenz verwenden.
- Plugin und BouncyCastle-Abhängigkeit aus vertrauenswürdigen Quellen beziehen.
- Release-Builds mit Authenticode signieren.
- Hashwerte für veröffentlichte Binärdateien bereitstellen.
- Eigenständige starke Transferpasswörter verwenden.
- `.kprx`-Dateien nach dem vorgesehenen Transfer sicher entfernen.
- Exportdateien nicht unkontrolliert per E-Mail oder Cloud-Speicher verteilen.
- Quellcode und Abhängigkeiten vor einem produktiven Einsatz einem Security Review unterziehen.

## Lizenzierung

Für eine Veröffentlichung sollte eine eigene Lizenzdatei für das Plugin ergänzt werden. Zusätzlich sind die Lizenzbedingungen der verwendeten BouncyCastle-Bibliothek zu beachten.

