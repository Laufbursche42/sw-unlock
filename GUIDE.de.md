# Anleitung

> **Machbarkeitsstudie.** Diese Seite zeigt, was das Bluetooth-Protokoll von Segway-Ninebot heute zugänglich macht. Sie ist kein fertiges Produkt. Ein fehlerfreier Betrieb wird nicht zugesichert und es gibt keine Gewähr. Was immer du damit tust, tust du auf eigenes Risiko und nur am eigenen Fahrzeug.

> **Wichtig für Fehler-Reports:** Schalte unten auf der Seite den **Diagnose-Log** ein, *bevor* du dich mit dem Scooter verbindest. Nur dann wird der komplette Verbindungsaufbau mitgeschnitten - und genau diese Zeilen brauchen wir in einem [Ticket](https://github.com/Laufbursche42/Laufbursche42/issues), um ein Problem nachzuvollziehen.

> **Schon mit dem Segway-Konto gekoppelt?** Dann gibt der Roller per Tastendruck oft kein frisches
> Pairing-Passwort mehr heraus, und der Handshake bleibt stecken. Am einfachsten verbindet sich ein
> Roller, der noch nie mit der App gekoppelt war.

## Was du brauchst

- Einen Segway-Ninebot-Scooter aus der offiziellen App `com.ninebot.segway`, eine von 17 unterstützten
  Familien (E-Serie, GT, Max, F, ES, P, C2 Pro, E2 und mehr).
- Einen Browser mit Web Bluetooth: **Chrome** oder **Edge** auf Android oder Desktop, **Bluefy** auf dem
  iPhone. Safari hat kein Web Bluetooth.
- Den Scooter an und in Reichweite.

## 1. Seite öffnen

Öffne die Seite im passenden Browser ([laufbursche42.github.io/sw-unlock](https://laufbursche42.github.io/sw-unlock/)).
Oben siehst du den Kopf mit Verbindungsstatus, dem Hell/Dunkel-Schalter und der Sprachumschaltung DE/EN.

## 2. Modell wählen

Der **Modell-Picker** listet 17 Scooter-Familien. Die Wahl deines Modells setzt Board, Register und
Frame-Generation für diese Familie **automatisch** und blendet Hebel aus, die das Modell nicht hat.
Wähle dein Modell vor dem Verbinden, damit die richtigen Register gesetzt sind.

## 3. Verbinden

Tippe auf **Verbinden** und wähle deinen Scooter im Bluetooth-Dialog. Die Seite erkennt den Ninebot-
Nordic-UART-Dienst und seine Schreib-/Notify-Merkmale automatisch. Lass beim ersten Mal alle Dienste und
Merkmale zu. Manche Scooter antworten erst, wenn sie wach sind - **kommt die Verbindung nicht zustande,
drück die Power-Taste am Roller**, damit er die Verbindung annimmt. Nach dem Verbinden steht der Status auf
**verbunden**, und der Encryption2-Handshake läuft automatisch.

## 4. Live-Werte lesen

Die Seite liest, was der Scooter meldet: Seriennummer, Firmware-Version, aktuelle Geschwindigkeit,
Akkustand, Fahrmodus und die BMS-Werte, die die Familie bereitstellt. Werte ohne gesicherte Grundlage sind
mit `[?]` markiert. **Alles auslesen** liest erneut, ohne neu zu verbinden. Lesen verändert nichts am
Scooter.

## 5. Erst lesen und plausibilisieren, dann schreiben

Nur das Speed-Register der E-Serie ist byteweise verifiziert; jedes andere Register ist Community-Quelle und
mit `[?]` gekennzeichnet. Lies zuerst den aktuellen Wert, prüfe, ob er für deinen Scooter plausibel ist, und
schreibe erst dann. Ein Echo im Log heißt, das Frame wurde **angenommen**; erst wenn die Einstellung mit dem
neuen Wert wieder in den Live-Werten auftaucht, ist bewiesen, dass sie wirklich **gewirkt** hat. Vor jedem
Schreiben kommt eine Sicherheitsabfrage.

## 6. Speed-Limit setzen oder lösen

Die Speed-Limit-Steuerung schreibt die Höchstgeschwindigkeit in km/h in das Speed-Register des Controllers
für deine Familie. Ein einzelner **Sperren/Entsperren**-Schalter drosselt auf den legalen Wert oder öffnet,
wo die Familie das anbietet. Fahrmodus (Eco / Drive / Sport), KERS (Aus / Mittel / Stark), Tempomat und
Rücklicht werden genauso gesetzt, wo unterstützt.

## 7. Seriennummer / Region zuerst sichern

Bevor du irgendetwas schreibst, lies **Seriennummer und Region** aus und **speichere das Backup** - ein
JSON-Download, der auch im lokalen Speicher liegt. Bei den Familien, die es unterstützen, kannst du die
Seriennummer über BLE neu schreiben, hinter einer Risiko-Checkbox und einer doppelten Bestätigung, oder sie
aus dem Backup wiederherstellen. Mach das Backup zuerst, damit du die Originalwerte immer zurücksetzen
kannst.

## 8. Roh-Register-Konsole für Experten

Für Experten liest die **Roh-Register-Konsole** jedes Register (Dekodierung als u8 / u16le / u16be / u32le /
ascii) und schreibt jedes Register hinter einer Bestätigung, mit fertigen Presets für jeden Speed-Hebel
beider Protokoll-Familien. Befehle, die einen Token brauchen, den das Tool nicht hat (den 16-Byte-
Identitäts-Token für "open ACC" / Wegfahrsperre), sind bewusst **nicht** verdrahtet.

## 9. Log anonymisiert teilen

Das **Protokoll** zeigt jedes gesendete und empfangene Frame als Hex mit Zeitstempel, dazu die dekodierten
Werte. Standardmäßig ist es **anonymisiert** - Adressen, Seriennummern und Geräte-IDs werden geschwärzt -,
damit du es gefahrlos teilen kannst. Mit **Log kopieren** oder **Als .txt speichern** gibst du den
Mitschnitt weiter, das hilft, das Protokoll am realen Gerät zu verstehen.

## Wenn etwas nicht klappt

- **Der Scooter taucht nicht in der Liste auf.** Ist er an und in Reichweite? Weck ihn mit der Power-Taste.
- **Kein Notify kommt an.** Prüfe im Log, ob RX-Zeilen erscheinen. Manche Modelle antworten erst nach einer
  kurzen Anlaufzeit oder nachdem du die Power-Taste gedrückt hast.
- **Ein Wert bleibt `[?]` oder leer.** Dann meldet die Familie diesen Wert über Bluetooth nicht, oder er ist
  Community-Quelle und ungetestet. Schick den Log, dann lässt sich der Ablauf nachziehen.

## Recht

Das Ändern des Speed-Limits entfernt die Drossel des Herstellers und lässt die ABE erlöschen; der Betrieb
auf öffentlichen Wegen ist dann nicht erlaubt und in vielen Ländern eine Straftat. Nutze das Werkzeug nur am
eigenen Fahrzeug auf privatem, abgesperrtem Gelände und auf eigenes Risiko. Siehe den
[Haftungsausschluss](DISCLAIMER.de.md).

## Mithelfen

Willst du herausfinden, ob und wie ein Register bei deinem Scooter geht? Teste dieses Tool an deinem eigenen
Fahrzeug und öffne ein [Ticket](https://github.com/Laufbursche42/Laufbursche42/issues) - mit
deinem Modell und was funktioniert hat (oder nicht), dazu dem anonymisierten Log. So verifizieren wir
gemeinsam, was jede Familie wirklich annimmt.
