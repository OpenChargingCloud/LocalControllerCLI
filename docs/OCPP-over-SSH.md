# OCPP und WWCP über SSH – Umsetzungsplan (Variante B)

Stand: 2026-11-06 · Pins: Hermod `bb6fd572` (origin/master `52ba3131`), WWCP_Core `e6417fde`,
WWCP_OCPP `4bdaee8f`, WWCP_Node `e591f759`, LocalController `01545ea3`; ChargingStation `9849710`,
CSMS `38c7368`.

## 0. Entscheidungen (Achim, 2026-11-06)

| # | Frage | Entscheidung |
|---|---|---|
| A/B | WebSocket im SSH-Kanal oder natives Protokoll | **B: natives Nachrichtenprotokoll über einen SSH-Subsystem-Kanal**, mit einer Transport-Abstraktion in Hermod, WWCP_Core und WWCP_OCPP |
| 1 | Subsystem-Namen | `ocpp@open.charging.cloud` **und** `wwcp@open.charging.cloud` |
| 2 | Listener im LC | **gemeinsamer SSH-Listener** des Nodes (neben Shell und SFTP); zusätzliche **AccessRules** können den Zugriff einschränken |
| 3 | Station-Identität | zuerst **einzelne Keys je Station**, eine SSH-CA später |
| 4 | LC-Uplink zum CSMS über SSH | später |
| 5 | Verbindungstyp | `IWebSocketConnection` wird in den Signaturen durch einen gemeinsamen Typ ersetzt, der WebSocket- **und** SSH-Verbindungen abbildet und sagt, **welche Variante** es ist, damit man an deren spezifische Eigenschaften kommt |

Ziel bleibt: Die Ladestation (CS) verbindet sich mit `ssh://lc.example.org[:port]` statt mit `wss://…`. LC und CSMS nehmen OCPP auch über SSH an. Die CS bietet optional selbst OCPP über SSH an, für das Commissioning. Das Zertifikats-Problem im privaten Netz löst sich so: Die CS pinnt den Host-Key des LC, und der LC kennt den Public Key jeder Station.

---

## 1. Ausgangslage

Die Verarbeitung ist schon transportneutral:
- `ProcessJSONMessage(JArray)` und `ProcessBinaryMessage(Byte[])`.
- Die 10 `SendJSON*`/`SendBinary*`-Methoden.
- Die Zuordnung von Antworten über `Request_Id`.
- Das Routing über `NetworkingNode_Id`.

Die **Typen** sind es nicht:

| Stelle | Kopplung an WebSocket |
|---|---|
| `IWebSocketConnection` / `WebSocket{Server,Client}Connection` | 2056 Treffer in WWCP_OCPPv2.1, 966 in v1.6, 50 in WWCP_CoreData, 31 in WWCP_OverlayNetworking, 25 in WWCP_OCPP_Common; fast alles wird nur durchgereicht, bis in die öffentlichen Event-Delegates |
| `Reachability`/`Routing` (WWCP_Core) | halten nur `IWWCPWebSocketClient?`/`IWWCPWebSocketServer?` |
| `OCPPAdapter.Send*` | `is OCPPWebSocketClient`/`is OCPPWebSocketServer` (konkrete Klassen, rund 20 Stellen je Version) |
| IN-Adapter | `switch (conn) { case WebSocketClientConnection … case WebSocketServerConnection … }` und `LearnRouteBack` |
| Identität | `IdentitiesOf` (URL-Pfad, TLS-CN, Basic, TOTP), `X-OCPP-NetworkingMode` als HTTP-Header |
| Text und Binär | getrennt über den WebSocket-Opcode |

**Wer außerhalb der Kernbibliotheken betroffen ist** (Treffer der drei Verbindungstypen):

| Projekt | Treffer |
|---|---|
| WWCP_EEBUS (EEBUSConformanceTests) | 31 |
| WWCP_POI | 8 |
| CSMS | 5 |
| LocalController | 4 |
| je eine MCP-Bibliothek (CSMS-, CS-, EMSP-CLI, OCPPCSMSInternal) | 2 |
| ChargingStation | 1 |
| GatewayCLI | 1 |
| OCPPCSMSInternal | 1 |

Die öffentlichen Delegates ändern sich zwar, aber außerhalb von WWCP_Core und WWCP_OCPP sind nur rund 55 Stellen anzufassen. Lambdas ohne Typangaben übersetzen weiter.

**Was Hermod schon hat:**
- `SshSessionChannel.ServeAsync` mit Subsystem-Namen und Resolver.
- `SshMuxChannel` mit `Input`, `SendDataAsync`, `Closed` und `AsStream()`.
- Den SSH-Client mit Publickey-Auth und `HostKeyPolicy`.
- `URIScheme.ssh`.
- `NetworkAcl`/`IpCidr`, die Vorbild für die AccessRules sind.

**Was Hermod fehlt:**
- `SshServerOptions` hat keinen allgemeinen Subsystem-Haken; `"sftp"` ist fest verdrahtet (`SshServer.cs:774-802`).
- `SshClient` hat kein `OpenSubsystemAsync`.
- Es gibt kein Nachrichten-Framing über einen Kanal.

---

## 2. Die Verbindungsabstraktion (Entscheidung 5)

**Ort:** Hermod, als neutraler Basistyp neben WebSocket und SSH.

Vorschlag Namespace `org.GraphDefined.Vanaheimr.Hermod.Messaging`:

```csharp
public enum MessageTransport { WebSocket, SSH }        // welche Variante
public enum ConnectionRole   { Client,    Server }     // wer hat gewählt: wir (Client) oder die Gegenseite (Server)

public interface IMessageConnection
{
    // Wer, was, wie
    String            ConnectionId            { get; }  // eindeutig, für Logs und Bookkeeping
    MessageTransport  Transport               { get; }
    ConnectionRole    Role                    { get; }
    String?           Subprotocol             { get; }  // ausgehandelt: "ocpp2.1", "ocpp1.6", "wwcp…"
    IPSocket          LocalSocket             { get; }
    IPSocket          RemoteSocket            { get; }

    // Zustand und Zähler
    DateTimeOffset    ConnectedSince          { get; }
    DateTimeOffset?   LastSentTimestamp       { get; }
    DateTimeOffset?   LastReceivedTimestamp   { get; }
    Boolean           IsAlive                 { get; }
    UInt64            MessagesSentCounter     { get; }
    UInt64            MessagesReceivedCounter { get; }
    UInt64?           MaxTextMessageSizeIn    { get; }   // usw. für Text/Binär, In/Out

    // Anwendungsdaten (heute nur an den Klassen, nicht im Interface)
    Boolean  TryAddCustomData   (String Key, Object? Value);
    Boolean  TryAddCustomData   (String Key, Object? NewValue, Object? ComparisonValue);
    Boolean  HasCustomData      (String Key);
    Object?  TryGetCustomData   (String Key);
    T?       TryGetCustomDataAs<T>(String Key);

    // Senden und Schließen
    Task<SentStatus> SendTextMessage  (String  Text,  CancellationToken CancellationToken = default);
    Task<SentStatus> SendBinaryMessage(Byte[]  Data,  CancellationToken CancellationToken = default);
    Task             Close            (String? Reason = null, CancellationToken CancellationToken = default);

    // Bequem: die Variante samt ihren Eigenschaften
    Boolean TryGetWebSocket(out IWebSocketConnection  WebSocket);   // => this is IWebSocketConnection
    Boolean TryGetSSH      (out ISshMessageConnection SSH);         // => this is ISshMessageConnection
}

public interface IWebSocketConnection  : IMessageConnection { /* wie heute: HTTPRequest, HTTPResponse, Frames … */ }
public interface ISshMessageConnection : IMessageConnection
{
    SshSessionInfo  Session          { get; }   // Login, Auth-Methode, Key-Fingerprint, Restriktionen, Peer
    String          Subsystem        { get; }   // "ocpp@open.charging.cloud" | "wwcp@open.charging.cloud"
    SshMuxChannel   Channel          { get; }
    Byte[]?         ServerHostKey    { get; }   // auf Client-Seite: der Host-Key, gegen den geprüft wurde
}
```

**Zugriff auf die Variante:** `Transport` und `Role` beantworten die Frage nach der Variante ohne Typprüfung, was für Logs und `switch` praktisch ist. Wer an die spezifischen Eigenschaften will, nutzt Pattern Matching (`if (conn is ISshMessageConnection ssh) … ssh.Session.PublicKeyFingerprint`) oder `TryGetWebSocket`/`TryGetSSH`.

**Konkrete Klassen:**
- `WebSocketServerConnection` und `WebSocketClientConnection` bleiben bestehen. Sie bekommen `Transport => WebSocket` und `Role => Server`/`Client`.
- Neu sind `SshMessageServerConnection` und `SshMessageClientConnection`.

**Name:** `ISshMessageConnection` statt `ISSHConnection`, weil Hermod schon eine Klasse `SshConnection` hat (Einkanal-Pfad). Gemeint ist nicht die ganze SSH-Verbindung, sondern ein Nachrichtenkanal darüber.

---

## 3. Das Wire-Protokoll im SSH-Kanal

1. **Verbindung und Auth:** Die CS verbindet sich per SSH mit dem LC.
   - Benutzername = `NetworkingNodeId` der Station, z. B. `cs001`.
   - Auth per Publickey, der Key ist beim LC an die Station gebunden.
   - Den Host-Key des LC hat die CS gepinnt, oder sie übernimmt ihn per TOFU beim Commissioning.
2. **Kanal:** `session`-Kanal, dann `subsystem "ocpp@open.charging.cloud"` bzw. `"wwcp@open.charging.cloud"`.
3. **Framing:** wie bei SFTP `uint32 Länge` (big-endian, zählt Typbyte plus Payload), dann `byte Typ`, dann die Payload.
   - Die Länge wird **vor** der Allokation gegen die Grenze geprüft (Lehre aus `6abdb089`).
   - Die Grenze ist je Richtung konfigurierbar, mit denselben Defaults wie `MaxTextMessageSizeIn` usw. beim WebSocket.

   | Typ | Name | Richtung | Payload |
   |---|---|---|---|
   | `0x01` | HELLO | C→S | JSON: `{"subprotocols":["ocpp2.1","ocpp2.0.1"]?, "networkingNodeId":"cs001"?, "networkingMode":"Standard"?, "maxMessageSize":…?}` |
   | `0x02` | WELCOME | S→C | JSON: `{"subprotocol":"ocpp2.1"?, "networkingNodeId":"cs001", "maxMessageSize":…}` |
   | `0x03` | REFUSED | S→C | JSON: `{"code":"…", "description":"…"}`, danach schließt der Server |
   | `0x10` | TEXT | beide | UTF-8, OCPP-J- bzw. WWCP-JSON-Array (wie WS-Textframe) |
   | `0x11` | BINARY | beide | Bytes (wie WS-Binärframe, z. B. `OCPP_Binary*Message`) |
   | `0x20` / `0x21` | PING / PONG | beide | beliebige Bytes, PONG wiederholt sie; RTT und Kanal-Lebendigkeit, ersetzt den WS-Ping |
   | `0x30` | CLOSE | beide | `uint16 Code` + UTF-8-Grund; danach EOF und Close des Kanals |

   Unbekannte Typen ≥ `0x80` werden ignoriert, das ist Raum für Erweiterungen. Unbekannte Typen unter `0x80` sind ein Protokollfehler, auf den CLOSE folgt.
4. **Aushandlung:**
   - Der Subsystem-Name trägt keine Version, deshalb handeln HELLO und WELCOME das Subprotokoll aus, wie `Sec-WebSocket-Protocol`.
   - `ocpp@` nutzt die bekannten IDs `ocpp1.6`, `ocpp2.0.1` und `ocpp2.1`.
   - Für `wwcp@` gibt es keine eigene ID (§7.1). Die Liste darf leer bleiben, und WELCOME nennt dann kein Subprotokoll.
   - Der Server antwortet innerhalb einer HELLO-Frist (Default 10 s, wie eine Login-Grace-Time), sonst schließt er.
   - Vor WELCOME sind keine TEXT- und BINARY-Frames erlaubt.
5. **Identität:**
   - Der SSH-Login ist die bewiesene Identität.
   - `networkingNodeId` im HELLO entspricht dem URL-Pfad bei WS. Ist sie leer, gilt der Login. Weicht sie ab, ist sie nur erlaubt, wenn `MayActFor` es erlaubt (Hubs, vom LC weitergereichte Ids). Sonst kommt REFUSED.
   - `networkingMode` entspricht dem Header `X-OCPP-NetworkingMode`.
6. **Senden:** genau ein Schreib-Lock pro Kanal. `SshMuxChannel.SendDataAsync` serialisiert nicht, ein Frame darf also nie mit einem anderen verschränkt werden.
7. **Lebendigkeit:**
   - SSH-Keepalive auf Client und Server (`ClientAliveInterval`), dazu optional PING.
   - Der Node setzt heute kein `IdleTimeout`; falls doch einmal, muss es größer als das Heartbeat-Intervall sein.
8. **Ende:**
   - CLOSE oder Kanal-Close beendet die Verbindung, danach folgt `Forget` im Bookkeeping.
   - Reconnect auf Client-Seite übernimmt eine Policy wie `WebSocketClientReconnectPolicy` (Backoff, Jitter, MaxAttempts). Jeder Versuch ist eine neue SSH-Verbindung.

Das Protokoll wird in Hermod unter `docs/` (oder einer README im Messaging-Ordner) als kurze Spezifikation festgehalten, damit Dritte es nachbauen können.

---

## 4. Gemeinsamer Listener und AccessRules (Entscheidungen 2 und 3)

**Ein SSH-Server je Node**, wie heute (`WWCPNode.StartedSSHServer`). Er bietet je nach Node-Art an:

| Dienst | Wer darf | Konfiguration |
|---|---|---|
| Shell (Node-CLI) | Konten mit Rollen (`NodeSSHAuthenticator`) | `ssh` |
| `sftp` | Konten | `ssh.sftp` |
| `ocpp@open.charging.cloud` | Stationen (Keys im Station-Store); auf der CS: Konten mit Commissioning-Recht | LC/CSMS: `ocppServer.ssh`; CS: eigener Abschnitt |
| `wwcp@open.charging.cloud` | WWCP-Nachbarknoten (Keys im Store der Node-Art) | Abschnitt der Node-Art |

**Authentifizierung:** `CompositeSSHAuthenticator` in WWCP_Node.
- Zuerst die Konten, dann von der Node-Art gelieferte Authenticatoren (LC: Stationen).
- Gibt es einen Login-Namen zugleich als Konto und als Station, wird abgelehnt. Beim Anlegen und beim Start erscheint eine Warnung.
- **Station-Logins** bekommen immer die Restriktionen `PermittedSubsystems = [ocpp@…, wwcp@…]` (nur die, die die Station darf), `no-pty` und `no-port-forwarding`. Keine Shell, kein Exec, kein SFTP.
- **Konten** bekommen die OCPP-/WWCP-Subsysteme nur mit ausdrücklichem Recht.

> **Stand 2026-11-06: auf master** (origin, git1, git2):
> - WWCP_Node `5e268eb`
> - Hermod `bfeb64f9`: `AuthorizeSession` und die echte lokale Adresse jeder Verbindung.
>
> Abweichungen vom Entwurf unten:
> - `service` kennt nur `shell`, `sftp` und `subsystem:<name>`. Exec und Forwarding bietet der Node nicht an.
> - `timeWindow` gibt es noch nicht.
> - Die Limits je Principal-Art (siehe unten) sind noch offen.
> - Regeln lassen sich auch als Zeilen in der Syntax der Kommandozeile schreiben. So schickt sie auch die Webseite.

**AccessRules** (neu, WWCP_Node, Abschnitt `ssh.accessRules`):
- Eine geordnete Liste; die erste passende Regel gewinnt.
- Sie **können nur einschränken**. `allow` heißt „weiter zur eingebauten Policy“, `deny` lehnt ab. Passt keine Regel, gilt `allow`, also die eingebaute Policy.
- **Dimensionen**, jede optional (fehlt sie, passt alles):
  - `principal`: `account:<id|glob>`, `station:<id|glob>`, `group:<loginGroup>`
  - `service`: `shell`, `sftp`, `exec`, `subsystem:<name>`, `forward`
  - `source`: CIDR-Liste der Gegenstelle (`IpCidr`; IPv4-mapped wird normalisiert, siehe Memory „IPNetwork quirks“)
  - `localAddress`: die eigene Adresse, an der die Verbindung ankam. Damit lässt sich z. B. OCPP nur auf der NIC des Stationsnetzes erlauben und die Shell nur auf der Uplink-NIC.
  - `authMethod`: `publickey`, `password`, `keyboard-interactive`, `certificate`
  - `timeWindow`: optional, später
- **Wo geprüft wird:**
  - Regeln ohne `service` beim Login (`AuthorizePublicKeyAsync`/`GetRestrictionsAsync`), damit abgewiesene Logins gar keine Session bekommen.
  - Regeln mit `service` beim Kanal- bzw. Subsystem-Request; im Audit erscheint dann `PolicyDeniedEvent` mit der Regelnummer.
  - Ändern sich die Regeln, prüft `WhyNoLongerIn` laufende Sessions erneut (alle 5 s, wie heute) und beendet sie.
- **Beispiel** (LC mit Uplink-NIC 192.0.2.10 und Stationsnetz 10.10.0.0/16 an 10.10.0.1):

  ```json
  "ssh": {
    "enabled": true, "port": 22, "sftp": true,
    "accessRules": [
      { "action": "deny",  "service": "subsystem:ocpp@open.charging.cloud", "localAddress": "192.0.2.10" },
      { "action": "deny",  "principal": "account:*", "localAddress": "10.10.0.1" },
      { "action": "allow", "principal": "station:*", "source": [ "10.10.0.0/16" ] },
      { "action": "deny",  "principal": "station:*" }
    ]
  }
  ```

- **Werkzeuge:**
  - CLI `sshAccessRules list|add|remove|move|test <principal> <service> <source> <local>`; `test` zeigt, welche Regel greift.
  - Eine Web-Seite neben der SSH-Seite.
  - Berechtigung `Permission.Edit(NodeResources.SSH)`.
- **Limits** beim gemeinsamen Listener:
  - Hermods `MaxConnections` ist global (Default 100) und reicht für einen LC mit 100+ Stationen nicht.
  - Lösung: im Node getrennte Obergrenzen je Principal-Art, z. B. `maxConnections: { accounts: 20, stations: 500 }`. Sie werden beim Login geprüft, damit Stationen die Admin-Zugänge nicht aussperren können.
  - Hermods globales Limit wird entsprechend höher gesetzt.

**Station-Keys** (Entscheidung 3):
- Im LC-Store `ChargingStationLogin.SshKeys`: OpenSSH-Zeile, Kommentar, `AddedAt`, `Enabled`.
- `AuthMethod.SSHKey` in `LoginGroup`.
- Eine CA folgt später. Hermods `SshCertificateAuthorityTrust` ist dafür schon vorhanden (Principal = Station-Id, Revocation über KeyId und Serial).

---

## 5. Arbeitspakete nach Repository

Größen: S ≈ ein Tag, M ≈ einige Tage, L ≈ eine Woche und mehr. Jedes Paket landet mit Tests im eigenen Repo, danach folgen die Pin-Bumps.

### 5.1 Hermod (M–L) – Grundlage, nicht brechend

> **Stand 2026-11-06: auf Hermod master** (origin, git1, git2):
> - `c39bc053`: Subsystem-Factory, `PermittedSubsystems`, `SshClient.OpenSubsystemAsync`/`Closed`.
> - `c15cadfe`: `IMessageConnection`, das SSH-Nachrichtenprotokoll und die Spezifikation in `Hermod/SSH/Messaging/README.md`.
>
> Die Pins von LC, CS-CLI und CSMS-CLI stehen noch auf älteren Hermod-Ständen.
>
> Abweichungen vom Entwurf in §2:
> - Wie der Client-Kontext zum Server gehört, steht jetzt in `ISshMessageConnection`: `Username`, `Session` nur auf dem Server, `ServerHostKey` nur auf dem Client, dazu `Hello`/`Welcome` und `MaxMessageSizeIn`/`Out`.
> - `Close` heißt im Basistyp `Close(MessageCloseCode, …)`. Ein Pflichtparameter vermeidet Mehrdeutigkeiten mit dem `Close()` der WebSockets.
>
> WWCP_OCPPv2.1 und v1.6 bauen dagegen ohne Fehler.

1. **`IMessageConnection`**, `MessageTransport`, `ConnectionRole`, `ISshMessageConnection` (§2).
   - `IWebSocketConnection : IMessageConnection`. Custom-Data-Methoden und `SendTextMessage`/`SendBinaryMessage`/`Close` wandern ins Interface; die WS-Klassen haben sie schon oder bekommen dünne Adapter.
   - **Nicht brechend:** Wer heute `IWebSocketConnection` nutzt, merkt nichts.
2. **Subsystem-Haken in `SshServerOptions`:** `(SshSessionInfo, String Name, CancellationToken) → Handler?`.
   - Der Handler bekommt einen Kontext wie `SshShellContext` (Session, Channel, `Closed`, `Stopping`) und schließt den Kanal am Ende.
   - Er wird mit dem SFTP-Resolver verkettet (`SshServer.cs:774-802`) und ins Session-Gate (`:720`) aufgenommen.
3. **`SshSessionRestrictions.PermittedSubsystems`:** `null` heißt alle. Wird in `SshSessionChannel` vor dem Lookup geprüft. Dazu `And()` (Schnittmenge) und `IsRestricted`.
4. **`SshClient.OpenSubsystemAsync(name)`** und ein `Closed`-/`Disconnected`-Signal am `SshClient`.
5. **SSH-Nachrichtenprotokoll** (§3):
   - `SshMessageFraming`: Lesen und Schreiben, Grenzen, Schreib-Lock.
   - `SshMessageServer`: Subsystem-Handler. Events analog zu `WebSocketServer`: `OnHello` zur Validierung und Auswahl des Subprotokolls (darf REFUSED liefern), `OnNewConnection`, `OnTextMessageReceived`, `OnBinaryMessageReceived`, `OnClosed`. Dazu HELLO-Frist und Registry der Verbindungen.
   - `SshMessageClient`: SSH verbinden, Subsystem öffnen, HELLO senden, Reconnect-Policy, Events. Optionen: `SshClientOptions`, Subsystem, Subprotokolle, Grenzen, Ping.
   - `SshMessageServerConnection`/`SshMessageClientConnection : ISshMessageConnection`.
   - Die Spezifikation liegt als Datei im Repo.
6. **Tests:**
   - Framing: Grenzen, Länge 0, unbekannte Typen, Frames über mehrere SSH-Pakete.
   - HELLO-Aushandlung: Treffer, kein Treffer, Frist, Frames vor WELCOME.
   - Nebenläufige Sender ohne Verschränkung.
   - Close aus beiden Richtungen und Abriss der SSH-Verbindung.
   - Reconnect.
   - `PermittedSubsystems` mit `force-command` (siehe `d2ab407a`).
   - Mutationsläufe je Sicherheitsprüfung.

**Voraussetzung:** Die beiden Fixes `d2ab407a` und `6abdb089` sind auf master (2026-11-06).

### 5.2 WWCP_Core (L) – brechend, im Gleichschritt mit 5.3

> **Stand 2026-11-06: Commit `8a0a1803` auf master** (von `e6417fde`), gepusht auf GitHub, git1 und git2. LC, CSMS und NTS-KE-Session sind informiert. Gepinnt (zusammen mit WWCP_OCPP `bc25eefd`) in LocalControllerCLI `4bbe9cf`, CSMSCLI `01584be` und ChargingStationCLI `e228672`, ohne Änderung an den Verbrauchern.
> - `IWWCPTransport`/`IWWCPClient`/`IWWCPServer`; `Reachability` hält `Client`/`Server`, `Routing` nimmt beide; `WWCPClientOf(connection)`, `NetworkingNodeIdOf(connection)`.
> - `WWCPSshServer` (Login = Networking Node, HELLO-`networkingNodeId` nur mit `AllowToActFor`, `networkingMode` nur per Name, neueste Verbindung gewinnt) und `WWCPSshClient` (Reconnect auch nach einem ersten Fehlschlag).
> - `AWWCPNetworkingNode.ConnectSshClient`/`AttachSshServer`, `Stop` schließt beide.
> - Delegates und `SentMessageResult` mit `IMessageConnection`; `MessageConnectionJSON.ToJSON()`.
> - Tests: 7 `SshTransportTests`, 9 Mutationen (alle rot); WWCP_Core_Tests 102/102, Overlay 28/28.
>
> Abweichungen: Der Name ist `AttachSshServer(WWCPSshServer)` statt `AttachSshSubsystem(…)`, weil der Aufrufer den Server baut. Punkt 3 (eine gemeinsame Registry für WS und SSH) ist **nicht** umgesetzt: `WWCPWebSocketServer` behält seine, `WWCPSshServer` hat dieselbe Logik als eigene Kopie. Punkt 7 läuft nicht über `TestCaseSource`, sondern als eigene SSH-Tests.

1. **Signaturen:** In WWCP_CoreData und WWCP_OverlayNetworking `IWebSocketConnection` durch `IMessageConnection` ersetzen. Betroffen sind die Delegates in `IWWCPWebSocketServer.cs:34-69` und `IWWCPWebSocketClient.cs:31-66`, die konkreten Verbindungstypen eingeschlossen.
2. **Neutrale Transport-Interfaces:**
   - `IWWCPServer` (Registry, `Send*`, Events mit `IMessageConnection`, `AllowToActFor`/`MayActFor`) und `IWWCPClient`.
   - `IWWCPWebSocketServer : IWWCPServer, IWebSocketServer` usw.
   - `AddOrUpdateHTTPBasicAuth` bleibt nur auf der WebSocket-Seite.
3. **Gemeinsame Logik per Komposition** statt Kopie: Registry (`Register`/`Supersedes`/`Forget`), Identitätsregeln (`MayActFor`), JSON-Parsing (`JSONMessages.ParseArray`) und das Bookkeeping kommen in eine Klasse, die `WWCPWebSocketServer` **und** `WWCPSshServer` nutzen. `IdentitiesOf` wird aufgeteilt: in den WS-Teil (Pfad, CN, Basic, TOTP) und den SSH-Teil (Login plus HELLO-Id).
4. **`Reachability`/`Routing`** auf `IWWCPClient?`/`IWWCPServer?` umtypisieren. Die Overloads in `Routing.AddOrUpdateStaticRouting` folgen; `AllWebSocketClients/Servers` werden zu `AllClients/Servers`, die WS-Varianten bleiben gefiltert erhalten.
5. **`WWCPSshServer`/`WWCPSshClient`:** auf `SshMessageServer`/`SshMessageClient` aufbauen, mit derselben Event- und Registrierungslogik wie die WS-Klassen.
6. **`ANetworkingNode`:**
   - `AttachSshSubsystem(String Subsystem, IEnumerable<String> Subprotocols, …)` liefert einen `WWCPSshServer`, der keinen eigenen Listener öffnet. Die Node-Art hängt ihn in den Subsystem-Haken des gemeinsamen SSH-Servers.
   - `ConnectSshClient(...)` analog zu `ConnectWebSocketClient` (`ANetworkingNode.cs:535-601`): Next Hop stempeln, statische Routen setzen, Networking-Mode über HELLO.
7. **Tests:** Die bestehenden WebSocket-Tests in `WWCP_Core_Tests/WebSockets` (Identity, ConnectionBookkeeping, CertificateIdentity, DateLikeStrings, SecretsInTheLog) laufen per `TestCaseSource` über **beide** Transporte, sofern der Test nicht WS-spezifisch ist. Dazu kommen SSH-spezifische Identitätstests (HELLO-Id ≠ Login, `MayActFor`).

### 5.3 WWCP_OCPP – Common, v1.6, v2.1 (L) – brechend, im Gleichschritt mit 5.2

> **Stand 2026-11-06: Commit `bc25eefd` auf master** (von `f1de4e03`), gepusht auf GitHub, git1 und git2. Braucht WWCP_Core `8a0a1803` und Hermod ≥ `c15cadfe` (den LC, CS und CSMS seit ihrem letzten Pin-Bump schon pinnen).
> - `IWebSocketConnection` → `IMessageConnection` an 2003 Stellen in 308 Dateien; IN-Adapter fragen `Role`; `LearnRouteBack` über `WWCPClientOf`.
> - Statt `IOCPPClient`/`IOCPPServer` ein Interface `IOCPPMessageTransport` mit den 10 `Send*`; die OCPP-Adapter senden über `reachability.Transport`.
> - `OCPPSshServer`/`OCPPSshClient`; `ConnectOCPPClient(URL, …)` (ws/wss/http/https → WebSocket, ssh → SSH) mit `OCPPClientConnectResult`; `ConnectOCPPSshClient(URL ssh://…, SshClientOptions, …)`; `AttachOCPPSshSubsystem(…)`. Versionen und Next Hop je OCPP-Version (2.1: `ocpp2.1`, `ocpp2.0.1`, `CSMS`; 1.6: `ocpp1.6`, `CentralSystem`).
> - Tests: 8 SSH-Tests in 2.1 (darunter Overlay-Networking mit gelernter Route zurück), 2 in 1.6, 7 Mutationen (alle rot); v2.1 2008/2008, v1.6 648/648, Node 156/156.
>
> LC, CS und CSMS bauen gegen beide Commits ohne Änderung, alle ihre Suiten grün (Pin-Bumps `4bbe9cf`, `e228672`, `01584be`). Offen: die übrigen Verbraucher (MCP nennt `IWebSocketConnection` nur auskommentiert; GatewayCLI, OCPPCSMSInternal, WWCP_EEBUS, WWCP_POI) in ihren eigenen Bump-Runden; Forwarding über einen LC hinweg ist über SSH nicht eigens getestet.

1. **Ersetzen per Suchen und Ersetzen:** `IWebSocketConnection` → `IMessageConnection` in den Adaptern (IN, OUT, FORWARD), `Delegates.cs`, `OCPPAdapter.Receive*` und `SendRequestState`. Rund 3000 Stellen, überwiegend mechanisch. Danach mit `rg` gezielt prüfen, wo WS-Mitglieder genutzt werden: `RemoteSocket` (ist im Basistyp) und `TryAddCustomData` (ist im Basistyp).
2. **IN-Adapter:** die `switch`-Blöcke über `WebSocketClientConnection`/`WebSocketServerConnection` (v2.1 IN.cs 397/404, 615/622, 751/758, 931/938, 1087/1094, 1197/1204; v1.6 entsprechend) durch `connection.Role` ersetzen. `LearnRouteBack` arbeitet über `IWWCPClient`.
3. **`OCPPAdapter.Send*`:** `is OCPPWebSocketClient`/`is OCPPWebSocketServer` durch Interfaces ersetzen (`IOCPPClient`/`IOCPPServer` mit den 10 `Send*`-Methoden; die WS- und die SSH-Klasse implementieren beide).
4. **`OCPPSshServer`/`OCPPSshClient`** in Common, auf `WWCPSshServer`/`WWCPSshClient`.
5. **Node-API:**
   - `AttachOCPPSshSubsystem(…)` mit Subprotokollen je Version.
   - `ConnectOCPPSshClient(URL ssh://…, NextHopNetworkingNodeId, SshClientOptions/OCPPSshClientSettings, …)`.
   - Optional ein `ConnectOCPPClient(URL, …)`, das nach Schema verzweigt (`ws`/`wss` → WebSocket, `ssh` → SSH).
   - Jeweils in Common und in den v1.6- und v2.1-Overrides (`AOCPPNetworkingNode.cs` beider Versionen).
6. **`NetworkConnectionProfile.ocppCsmsUrl`:** `ssh://` wird schon geparst; als nicht standardkonform dokumentieren. Den Profilwechsel zu einer echten Verbindung gibt es noch nicht, das ist ein eigenes Thema.
7. **Tests:** TestChargingStationNode ↔ TestLocalControllerNode/TestCSMSNode über SSH: Boot, Heartbeat, Request in beide Richtungen, BinaryDataTransfer/SendFile, Overlay-Forwarding, Reconnect. Für v1.6 eine kleinere Auswahl.

**Brechende Änderung koordinieren** (siehe Memory „Shared libraries, parallel sessions“):
- 5.2 und 5.3 in einem kurzen Fenster umsetzen und vorher allen CLI-Sessions ankündigen.
- Danach die Verbraucher anpassen: LocalController (4), CSMS (5), ChargingStation (1), MCP (je 2), GatewayCLI (1), OCPPCSMSInternal (1), WWCP_EEBUS (31), WWCP_POI (8).
- Jede CLI übernimmt die neuen Pins in ihrer nächsten Bump-Runde. Bis dahin bleibt sie lauffähig, weil sie auf den alten Pins steht.

### 5.4 WWCP_Node (M–L) – parallel zu 5.2 und 5.3 möglich

> **Stand 2026-11-07: Punkte 1, 2, 5 und 6 umgesetzt, Commit `02d876f` auf master** (von `5e268eb`), gepusht auf GitHub, git1 und git2. Punkt 3 ist seit `5e268eb` auf master. Gepinnt in LocalControllerCLI `d253967`, ChargingStationCLI `4ff67a3` und CSMSCLI `fd873dc` (nur WWCP_Node bewegt; Lösungen bauen, WWCP_Node 1351/1351 je CLI, LocalController 585/585, Station 782/782, WWCP_OCPP_Node 156/156, CSMS 654/654, LC-Exe-Smoke grün).
> - **Haken:** `AddSSHSubsystem(new SSHSubsystem(Name, Label, Handler, ForAccounts))` und `RemoveSSHSubsystem(Name)`, jederzeit, ohne Neustart des SSH-Servers. Beim Entfernen enden die offenen Sessions. Hermod bekommt eine Factory (`SshServerOptions.Subsystems = SubsystemFor`). `sftp` bleibt der Node vorbehalten.
> - **Konten** bekommen ein Subsystem nur mit der Permission `ForAccounts`. Ist sie `null`, bekommt es kein Konto.
> - **Logins einer Node-Art:** `AddSSHSignIns(ISSHSignIns)` statt eines eigenen `CompositeSSHAuthenticator`. `NodeSSHAuthenticator` fragt die Art selbst (`Knows`, `AuthorizePublicKeyAsync`, `GetRestrictionsAsync`, `SubsystemsFor`, `GroupsOf`, `WhyNoLongerIn`).
>   - Solche Logins sind immer eingeschränkt: kein Pty, kein Forwarding, `PermittedSubsystems` = die Subsysteme der Art ohne `sftp`. Die Art kann das nur weiter einschränken.
>   - Ein Name, der zugleich Konto und Login ist, wird als keins von beiden eingelassen. Beim Start und bei jedem Versuch (höchstens einmal je Minute und Name) erscheint eine Warnung. `SSHLoginOf(name)` können Arten beim Anlegen fragen.
>   - Wie eine Verbindung sich angemeldet hat, merkt sich die Node an der Tür (`AuthorizeSession`), damit ein später umbenannter Name die Session nicht umdeutet.
> - **Prüfung je Subsystem-Session:** AccessRules (`subsystem:<name>`, Station als `station:<id>` mit ihren Gruppen), Login noch gültig, Permission des Kontos bzw. Subsystem-Liste der Station.
>   - Geprüft wird vor dem Bedienen, alle `SSHSessionRecheckEvery` und sofort bei Regeländerung oder `RecheckSSHSessions()` (jetzt öffentlich, für die Art nach einem Key-Entzug).
>   - Eine Session, die nicht weiter darf, endet: Das Token des Handlers feuert und der Kanal wird geschlossen, auch wenn der Handler das Token ignoriert.
> - **Anzeige:** `SSHSession` hat zusätzlich `Principal`, `SubsystemName` und `Label`. `who` zeigt z. B. „cs001 (station)  with OCPP from …“, und die SSH-Seite und ihr JSON nennen beides. `Audited` nennt bei Ablehnungen den Grund und bei Unbekanntem, was bedient wird.
> - `SSHPrincipalFor(session)` hilft Handlern, die Konten und Stationen unterschiedlich bedienen (z. B. NTS-KE nach Whitepaper §8.3).
> - **Abweichung:** `SSHSession.Kind` ist `"subsystem"` mit Name und Label statt `"ocpp"`/`"wwcp"`. Das OCPP-Subprotokoll (z. B. „ocpp2.1“) kennt die Node nicht, es fehlt deshalb in `who`.
> - **Tests:** `SSHSubsystemTests` (11) und 12 Mutationen der Prüfungen, alle rot. Frontend 693/693.
> - **Punkt 4 (2026-11-08):** WWCP_Node `0d0f8e0` auf `ba72874`, gepusht 2026-11-08, gepinnt in LocalControllerCLI `4937d55`.
>   - `"ssh": { "maxConnections": { "account": 20, "station": 100 } }`: Verbindungen je Art. Default 20 für Konten und 100 für jede Login-Art einer Node-Art, erlaubt 1–10000.
>   - Gezählt wird ab der Anmeldung an der Tür (`AuthorizeSSHSession`) bis zum `ConnectionClosedEvent`, das Hermod für jede Verbindung im `finally` meldet. Das Token von `AuthorizeSession` taugt dafür nicht: Hermod bricht es nur beim normalen Ende ab, eine verlorene oder kaputte Verbindung räumt es ohne Abbruch weg.
>   - Ist eine Art voll, wird die nächste Verbindung an der Tür abgewiesen. Das Log meldet das je Art höchstens einmal pro Minute, mit der Zahl der seither stillschweigend Abgewiesenen.
>   - Hermods `MaxConnections` ist die Summe aller Arten plus 10 noch nicht Angemeldete: 130 für einen LC mit Stationen.
>   - Eine Änderung gilt je Art sofort; offene Verbindungen über der Grenze bleiben. Gesendete Arten werden zusammengeführt wie in der Datei. Die Summe für den Server gilt ab seinem nächsten Start; bis dahin sagt es der Hinweis in der Antwort.
>   - Die SSH-Seite zeigt `limits.byKind`.
>   - Tests: `SSHConnectionLimitTests` (5), 17 Mutationen rot, WWCP_Node 1406/1406, LC 603/603, Frontend 707/707.
> - **Offen:** nichts. Laut grep nutzt keine Node-Art in keiner CLI, was sich geändert hat.

1. **Subsystem-Haken für Node-Arten:** etwa `protected virtual SshSubsystemHandler? SubsystemFor(SshSessionInfo, String)` oder eine Registry `RegisterSshSubsystem(name, handler, permission)`. Wird in `StartedSSHServer` (`WWCPNode.SSH.cs:447-479`) an Hermod übergeben.
2. `CompositeSSHAuthenticator` und Station-Restriktionen (§4).
3. **AccessRules:** Engine, Konfiguration (`SSHConfiguration`: Parsen, Schreiben, `TryUpdateSSHConfiguration`), CLI-Befehl, Web-Seite, `test`-Funktion, Audit mit Regelnummer, Neuprüfung laufender Sessions.
4. **Limits je Principal-Art.** Hermods `MaxConnections` passend setzen.
5. **Session-Arten:** `SSHSession.Kind` um `"ocpp"`/`"wwcp"` erweitern; Anzeige in `who` („OCPP as cs001, ocpp2.1“), in `SSHConfigurationJSON` und auf der SSH-Seite. Die Texte in `Audited` (`:931-943`) anpassen.
6. **Tests:** Regelauswertung (first-match, nur einschränkend, `localAddress`, IPv4-mapped), Station-Login ohne Shell/SFTP/Forwarding, Kollision Konto/Station, Neuprüfung nach Regeländerung, Limits je Art. Alle Node-Arten bauen gegen die Änderung (siehe Memory „Base change: check every override“).

> **Hinweis aus der NTS-KE-Session (2026-11-06):** Das Whitepaper OpenChargingTechnology/Whitepapers `NTS-over-SSH/README.md` definiert NTS-KE als Subsystem `ntske/1@open.charging.cloud`. Geplant ist ein eigener Hermod-SSH-Listener in Norn. Soll NTS-KE einmal auf dem gemeinsamen Listener einer Node laufen, dann über diesen Haken, und zwei Dinge betreffen sein Design:
> - Schlüsselvariante A braucht einen Exporter je Verbindung (Zugriff auf K/H/session_id oder `SSH-Exporter(label, context, L)` auf der Verbindung). Außerdem braucht sie den Zustand „höchstens ein `ntske/1@` je Verbindung“, sonst leitet ein zweiter Austausch dieselben Schlüssel ab. Bei langlebigen OCPP-über-SSH-Verbindungen ist das relevant. Variante B (Pflicht) braucht beides nicht.
> - Station-Restriktionen (`PermittedSubsystems`) müssen `ntske/1@open.charging.cloud` zulassen können.

### 5.5 LocalController (M–L)

> **Stand 2026-11-08: Punkte 1–6 umgesetzt und in LocalControllerCLI gepinnt.**
> - **LocalController:** `a1e0c36` (Punkte 1–5, von `c9eea3e`), darauf `500eb45` der LC-Session (nur das Frontend-Lockfile) und `0e812d5` (die SSH-Adresse, siehe unten). Alles auf master und gepusht auf GitHub, git1 und git2.
> - **LocalControllerCLI:** `9cc28e7` (LC-Session: alle Libraries auf ihren master), darauf `9dea0df` (`stationKeys`, die Banner-Zeile, README). Gepinnt ist LocalController `0e812d5`.
> - **Konfiguration:** `ocppServer.ssh` mit `enabled` (Default aus), `subprotocols` (Default: die des WS-Ports), `maxMessageSize` (Default 16 MiB, 64 KiB–64 MiB) und `pingEverySeconds` (Default 30 s). An und aus ohne Neustart, nur solange der Stationsserver läuft. Die übrigen Felder warten auf den Neustart (`ssh.subprotocols` usw. in `waitingForARestart`). `helloTimeout` fehlt: `AttachOCPPSshSubsystem` nimmt keinen, es gilt Hermods Default von 10 s.
> - **Stores:** `ChargingStationLogin.SSHKeys` als Hermods `UserSSHKey` (authorized_keys-Zeile; `from=` und `expiry-time=` gelten), `TryAddSSHKey` (legt die Station an, falls nötig), `TryRemoveSSHKey`, `FindSSHKey`. Ein Key gehört zu genau einer Station, auch in einer von Hand geschriebenen Datei. `cert-authority`-Zeilen werden abgelehnt. Eine Station darf nicht wie ein Konto heißen (`TryAddStationSSHKey`). `AuthMethod.SSHKey` (`"sshkey"`): Die Gruppe entscheidet. Security-Profile werden nicht abgefragt. Die Default-Gruppe eines neuen LC nimmt Keys an, eine Default-Gruppe aus einer bestehenden Datei bleibt, wie sie ist.
> - **Station-Logins:** `StationSSHSignIns : ISSHSignIns` (statt Composite, siehe 5.4). Nur Stationen mit Key sind Logins, Principal `station:<id>` mit ihrer Gruppe. Abgelehnt werden eine Station oder Gruppe, die abgeschaltet ist, eine Gruppe ohne `sshkey`, ein Key, der entfernt oder abgelaufen ist, und jeder Login, während OCPP über SSH aus ist. Laufende Sessions enden sofort, weil `OnChanged` des Stores `RecheckSSHSessions()` auslöst. Ablehnungen mit behebbarer Ursache landen höchstens einmal je Minute im Log.
> - **HELLO:** bleibt bei `WWCPSshServer.Validate` (Login = Station, HELLO-Id nur mit `AllowToActFor`). Die Gruppe ist schon beim SSH-Login geprüft, das Subprotokoll handelt `SshMessageServer` aus.
> - **HTTP-API:** `POST …/stations/{id}/sshKeys`, `DELETE …/stations/{id}/sshKeys/{fingerprint}`. Das JSON des Stationsservers enthält `ssh` mit URL, Host-Key und Verbindungen.
> - **Frontend:** Auf „Logins and groups“ lassen sich Keys geben und entfernen, die Seite warnt bei Gruppen ohne `sshkey`, und das Gruppenformular hat `sshkey`. Die Stationsserver-Seite hat eine Karte „OCPP over SSH“ mit Schalter, URL, Host-Key und einer Warnung, wenn der SSH-Server aus ist.
> - **Tests:** `StationSSHTests` (14). 18 Mutationen, 17 davon rot. Grün bleibt nur „Gruppe aus ignoriert“, weil `LoginGroup.Allows` die Gruppe ohnehin verlangt. Frontend 114/114.
> - **CLI (`9dea0df`, Punkte 5 und 6):**
>   - `stationKeys [<station> [add <authorized_keys-Zeile> | remove <fingerprint>]]` gibt es an der Konsole und über SSH. Über SSH gelten dieselben Rechte wie im Webinterface: Lesen der Stationen zum Auflisten, Ändern zum Geben und Entfernen.
>   - Neben einem Key steht, warum er seine Station nicht hereinlässt: Station oder Gruppe aus, Gruppe ohne `sshkey`, OCPP über SSH aus oder kein SSH-Server.
>   - Das Banner hat unter `stations` eine zweite Zeile `ssh://…, subsystem ocpp@open.charging.cloud, N with an SSH key`. Den Host-Key zeigt der Eintrag `SSH`.
> - **Fix `0e812d5`:** `OCPPServerSSHURL` war der SSH-Port unter der Adresse des Stationsservers, also `ssh://0.0.0.0:22350`. Der SSH-Server lauscht aber nur auf dem Loopback, solange `--any` fehlt. Jetzt gilt der erste Name aus `reachableAs`, sonst die URL des SSH-Servers. Der Test `WhereTheStationsConnect_IsWhereTheSSHServerListens` war vorher rot.
> - **Tests an den Pins von `9cc28e7`:**
>   - LocalControllerTests 603/603.
>   - Die CLI hat kein Testprojekt. 7 Tests außerhalb des Repos decken Konsole und SSH ab, Ablehnungen und Rollen. 15 Mutationen, alle rot.
>   - 4 Smoke-Starts des Exe.
> - **Offen in 5.5:** nichts. Punkt 4 (Neuprüfung) ist erledigt.
> - **Nachtrag (2026-11-09, aus 5.7, gepusht auf GitHub, git1 und git2):** LocalController `b4f5070` auf `d8dcecd` (OpenADR-VEN): `StationSSHTests` prüft, dass der Key einer in der Datei abgeschalteten Station niemanden einlässt (`ChargingStationLogins.FindSSHKey`); mit der Mutation „`!login.Enabled` weg“ blieben vorher alle 15 grün. LocalControllerCLI `0208119` auf `75e4e00`: Pin dazu, und die SSH-Zeilen des Banners stehen je auf zwei Zeilen (vorher 93 bzw. 116 Spalten, jetzt höchstens 73). LocalControllerTests 629/629, 4 Smoke-Starts.

1. **Konfiguration `ocppServer.ssh`:** `enabled`, `subprotocols` (Default wie bei WS), `helloTimeout`, Nachrichtengrenzen, `pingEverySeconds`.
   - Parsen, Schreiben und `NeedsARestartFor`. Da der Listener gemeinsam ist, ist kein Neustart nötig; das Subsystem wird nur an- oder abgeschaltet.
   - `wwcp@` folgt, sobald der LC einen WWCP-Overlay-Knoten betreibt.
2. **Stores:** `ChargingStationLogin.SshKeys`, `ChargingStationLogins.TryAddSshKey`/`TryRemoveSshKey`/`FindBySshKey`, `AuthMethod.SSHKey`.
3. **Station-Authenticator** für den Composite (Login = Station-Id, Key aus dem Store, Station aktiv, Gruppe erlaubt `SSHKey`). Dazu die Prüfung im HELLO-Handler (Id, Gruppe, Subprotokoll). `ValidateStation` bleibt WS-spezifisch; gemeinsame Teile (aktiv, Gruppe) werden herausgezogen.
4. **Neuprüfung laufender Sessions:** Wird ein Key entfernt oder eine Station deaktiviert, wird getrennt.
5. **HTTP-API, Frontend, CLI:**
   - `…/stations/{id}/sshKeys`; `stationLogins.ts`: Keys anzeigen, hinzufügen und entfernen, mit Fingerprint.
   - `stationKeys <id> list|add|remove`.
   - Host-Key-Fingerprint des LC als Info für die Inbetriebnahme.
6. **Banner und `OCPPServerURL`:** zusätzlich `ssh://host:port` mit dem Host-Key-Fingerprint.
7. **Verbraucher-Anpassungen aus 5.3** (4 Stellen) beim Pin-Bump.

### 5.6 ChargingStation (ChargingStationCLI, M)

1. **Client:**
   - `ConnectionEntry`: `ssh` in `AllowedSchemes`/`Validate` (`:129`, `:421`), `IsSecure` = wahr.
   - Neues Feld `HostKey`: Fingerprint, `@cert-authority`-Zeile oder `"tofu"`.
   - Eigene known_hosts-Datei. TOFU nur ausdrücklich; ein Wechsel des Host-Keys wird gemeldet, nicht übernommen.
2. **Identität:** Beim ersten Start einen Key `ssh/ocpp_id_ed25519` erzeugen und den Fingerprint in CLI und Web zeigen. `AuthenticationEntry.AuthenticationKind.SSHKey`.
3. **`Dial`/`TestConnection`/`DialAgain`/`HangUp`:** bei `ssh` `ConnectOCPPSshClient` nutzen; `ClientOf` wie bisher über `RemoteURL`.
4. **Server für das Commissioning** (optional):
   - `ocpp@` auf dem Node-SSH-Server der CS, angehängt an `cs01`/`cs02` per `AttachOCPPSshSubsystem`.
   - Zugelassen sind Konten mit dem Recht `Commissioning`; sie treten als `NetworkingNode_Id.CSMS` auf (`MayActFor`).
   - Noch zu klären: wie die Route einer Commissioning-Verbindung neben dem regulären Uplink zu `CSMS` priorisiert wird, oder ob das Werkzeug eine eigene Node-Id bekommt.
5. **Verbraucher-Anpassung aus 5.3** (1 Stelle).

> **Stand 2026-11-08:** Punkte 1–3 sind in ChargingStation `256d77f`, gepinnt in ChargingStationCLI `a36d48b`.
> - `ssh://` geht über `ocpp@open.charging.cloud`, angemeldet mit dem eigenen Ed25519-Key der Station. Die Seite *Connections* zeigt dessen öffentlichen Teil.
> - Der Host-Key wird je Verbindung gepinnt.
> - **Abweichung von Punkt 1:** Ist kein Host-Key eingetragen, glaubt die Station dem ersten gezeigten Key und schreibt ihn fest (`SshHostKeyTrust.Verify`, `PinIfFirst`). Das ist TOFU ohne ausdrückliches `"tofu"`, wie `StrictHostKeyChecking=accept-new`. Ein späterer Wechsel wird abgelehnt.
> - **Offen:** Punkt 4 (Commissioning-Server) und die Frage dazu in 7.3.
>
> **Stand 2026-11-09: Punkt 4 umgesetzt, gepusht auf GitHub, git1 und git2.** ChargingStation `4b36729` auf `3b60262`, gepinnt in ChargingStationCLI `f5443e5` auf `b502483` (alle Bibliotheken an ihrer Spitze; dort erneut getestet).
> - `ocpp@open.charging.cloud` auf dem SSH-Server der Station, bedient vom OCPP-2.1-Knoten (`test02`, `ocpp2.1`/`ocpp2.0.1`), für Konten mit `commissioning:run`. `commissioning` ist eine neue Ressource; der Installer darf sie ändern und ausführen, der Systemadministrator über `*:run`.
> - **Entscheidung zu 7.3: eine eigene Node-Id**, nämlich das Konto, nicht `CSMS`. Grund: WWCP_Core hält je Ziel und Priorität genau eine Route, jede Registrierung nutzt Priorität 0, die neueste Verbindung gewinnt, und Lebendigkeit wird nicht geprüft. Ein Werkzeug als `CSMS` nähme dem Uplink die Route weg, mit allem, was die Station dem CSMS schickt, und mit ihren Antworten an ihn; nach dem Trennen zeigte die Route ins Leere, bis der Uplink sich zufällig neu verbindet. Darum hält das HELLO das Login; ein HELLO mit anderer Id und ein Konto, das wie `CSMS` oder die Station heißt, werden abgelehnt.
> - Im Standard-Networking adressiert der IN-Adapter Requests über eine fremde (Server-)Verbindung an `CSMS`, wie für einen LC in der Mitte. Eine Station hat nichts unter sich: Ihr 2.1-Knoten nimmt `CSMS` als eigene Anycast-Id, sodass ein Request des Werkzeugs für die Station ist und dem Werkzeug beantwortet wird. Eigene Requests der Station gehen weiter über den Uplink.
> - **Abweichung:** nur OCPP 2.1/2.0.1, nicht 1.6 (`cs01`). Ein Subsystem hat einen Handler, und das HELLO mit der Version liest der Message-Server selbst.
> - Jeder neu gebaute 2.1-Knoten (neue EVSEs, neues Typenschild) bekommt seinen Server; das Subsystem geht an den neuen, die Werkzeuge des alten werden getrennt.
> - Konfiguration `"commissioning": { "enabled": true }`, ohne Neustart; `GET`/`PUT /api/v1/configuration/commissioning`; Seite *Commissioning*; Banner-Eintrag `commissioning` in zwei Zeilen (höchstens 74 Spalten); README beider Repos.
> - **Tests:** `CommissioningOverSSHTests` (7), darunter: Bei einem CSMS am Uplink gehen die ausgelöste BootNotification und die Antwort an den CSMS über den Uplink, während ein Werkzeug verbunden ist. 21 Mutationen, alle rot (zwei erst, nachdem der Test fragte, an welchem Knoten das Werkzeug hängt). Frontend 6 Tests, 8 Mutationen rot, 352/352. ChargingStationTests 816/816, die Lösung baut, 3 Smoke-Starts (OpenSSH bekam das Subsystem als `root`).

### 5.7 CSMS (CSMSCLI, S–M)

- Stores und Station-Authenticator aus 5.5 spiegeln (`CSMSCLI/libs/CSMS/CSMS/OCPP/*`) und `ocppServer.ssh` übernehmen. Jeden LC-Store-Commit per SHA an die CSMS-Session nennen.
- Verbraucher-Anpassungen (5 Stellen).

> **Stand 2026-11-08: umgesetzt, gepusht auf GitHub, git1 und git2.**
> - **CSMS:** `9a50ec6` auf `41fbc7d`, direkt auf master. Übernommen aus LocalController `a1e0c36` und `0e812d5`:
>   - `ChargingStationLogin.SSHKeys` mit `TryAddSSHKey`/`TryRemoveSSHKey`/`FindSSHKey` und `AuthMethod.SSHKey` (`"sshkey"`).
>   - `StationSSHSignIns` mit der Neuprüfung über `OnChanged`.
>   - `ocppServer.ssh` samt `ssh`-Block im JSON des Stationsservers und `…/stations/{id}/sshKeys`.
>   - Die Frontend-Teile und die SSH-URL (erster Name aus `reachableAs`, sonst die URL des SSH-Servers).
>   - Die eigenen Abweichungen der CSMS-Store-Kopien bleiben.
> - **CSMSCLI:** `35b0f95` auf `ee90c06`, auf master: Pin CSMS `9a50ec6`, `stationKeys` (Konsole und SSH, Rechte wie im Webinterface), Banner, README. Die übrigen Pins bleiben (Hermod `5c974c5d`, WWCP_Node `ba72874`, WWCP_OCPP `9f93566c`).
> - **Abweichungen vom LC:**
>   - Die Banner-Zeilen zu SSH sind je zwei Zeilen: auf einer waren sie 93 bzw. 116 Spalten breit, und das Banner bricht die Zeilen einer Art nicht um. Im LC seit LocalControllerCLI `0208119` ebenso (siehe 5.5, Nachtrag).
>   - `StationSSHTests` prüft eins mehr: Der Key einer in der Datei abgeschalteten Station lässt niemanden ein (`ChargingStationLogins.FindSSHKey`). Das hielt vorher kein Test.
> - **Tests:**
>   - `StationSSHTests` (15): vor der Portierung rot (das Testprojekt baute nicht, 64 Fehler), danach grün. 27 Mutationen, 25 rot. Grün bleiben „Gruppe aus ignoriert“ (hält `LoginGroup.Allows`, wie im LC) und „Subsystem auch ohne Bedienung“ (dann wird keine Station eingelassen).
>   - CSMSTests 672/672. Frontend 155/155, die 3 neuen gegen die alten Seiten rot. Typecheck sauber, die Lösung baut.
>   - `stationKeys`: 7 Tests außerhalb des Repos, an der Konsole und in einer echten SSH-Shell (viewer abgewiesen, cpo eingelassen). 16 Mutationen, alle rot.
>   - 4 Smoke-Starts einer Kopie des Exe: an, mit `reachableAs`, mit `--no-ssh`, aus. Beim ersten meldete sich OpenSSH mit dem Key als Station an und öffnete `ocpp@open.charging.cloud`; eine Shell wurde abgewiesen.
> - **Verbraucher-Anpassungen:** keine mehr nötig. Die CSMS baut gegen WWCP_OCPP `9f93566c`; nur `PKISetup.cs` hat noch einen auskommentierten `ConnectOCPPWebSocketClient`.
> - **Pins nachgezogen (2026-11-09):** CSMSCLI `997bce0` der CSMS-CLI-Session, gepusht, CI grün. Damit hat CSMSCLI WWCP_Node `0d0f8e0` (eigene SSH-Grenzen für Stationen und Konten), WWCP_OCPP `f88842f4` (binärer SEND) und Hermod `a70b65b7` (Exit-Status der Subsysteme, CLOSE kurz vor dem Ende). Noch nicht WWCP_OCPP `ef49eba6` (siehe 5.8).

### 5.8 Integration

- Pin-Bumps in LC, CS-CLI, CSMS-CLI und den übrigen CLIs mit WWCP_OCPP-Pin (Gateway, OCPPCSMSInternal, OCPPConformanceTests, EVChargingTestEnvironment, EEBUSConformanceTests).
- Prüfung wie bisher: Build, Suiten, Smoke-Test der Exe, Banner nennt die Pins.
- **E2E** LC ↔ CS über SSH: Boot, Heartbeat, Kommando LC → CS, Binärpfad, Reconnect nach LC-Neustart, WS- und SSH-Stationen gleichzeitig am selben LC.
- **Negativfälle:**
  - falscher Host-Key
  - unbekannter Key
  - HELLO-Id ≠ Login
  - kein HELLO innerhalb der Frist
  - Station versucht Shell, SFTP oder Forwarding
  - Konto ohne Recht versucht `ocpp@`
  - eine AccessRule sperrt eine Station
  - Key wird bei laufender Session entfernt
  - zu großes Frame

> **Stand 2026-11-08: E2E in EVChargingTestEnvironment `b8cfc97` auf master, gepusht auf GitHub, git1 und git2.**
> - **Pin-Bump `6ede34b`:** alle Libraries auf ihrem origin/master vom 2026-11-08, darunter LocalController `0e812d5`, ChargingStation `6acc6eb`, WWCP_OCPP `c21aa445`, WWCP_Node `c042853` und Hermod `2113faad`.
>   - Ausnahme WWCP_ISO15118: `ff8eb69` statt `d2a7157`. `d2a7157` gibt `TcpV2GClient.ConnectAsync` einen `IDNSClient`, und EV master (`01c3407`) ruft es noch auf die alte Art auf, baut also nicht.
>   - Nachgezogen: ein V2G-Link je EVSE (ChargingStation `b45c96e`), `ocpi.remoteNetworks` für den CSMS (CSMS `5fe4e43`, sonst ruft er den EMSP auf dem Loopback nicht), `nts.groups` in den Tests.
>   - Build 0 Fehler, Tests 2/2, ein Start der Umgebung: alle fünf laufen, das OCPI-Peering steht.
> - **`OCPPOverSSHTests` (16):** ein echter LocalController und eine echte ChargingStation. Die Station wählt `ssh://cs001@127.0.0.1:<port>` mit ihrem eigenen Ed25519-Key. Was die Station nicht tun kann (kein HELLO, Shell, Forwarding, zu großes Frame), übernimmt ein Hermod-`SshClient` mit einem Station-Key, gegen denselben LC.
>   - Positiv: Boot (über SSH als `cs001`, `ocpp2.1`) und Heartbeat; Kommando LC → CS (`TriggerMessage`, danach der ausgelöste Boot); `BinaryDataTransfer` in beide Richtungen als BINARY-Frames; Reconnect nach LC-Neustart (gleicher Host-Key, der Pin bleibt); eine WS- und eine SSH-Station gleichzeitig.
>   - Negativ: gepinnter fremder Host-Key; unbekannter Key; HELLO-Id ≠ Login (`ssh://cs001@…/cs999`); kein HELLO in 10 s; Shell, Exec, SFTP, `direct-tcpip` und `tcpip-forward`; das Admin-Konto ohne Recht auf `ocpp@`; AccessRule `deny station:cs001 subsystem:ocpp@…`; Key-Entzug bei laufender Session; TEXT-Frame über `maxMessageSize` (64 KiB) → CLOSE 1009 schon auf den Kopf hin.
>   - **TOFU:** `HostKey_NonePinned_TheFirstOneShownIsBelievedAndPinned_ImplicitTOFU` hält das heutige Verhalten fest (5.6). Gilt TOFU künftig nur mit `"tofu"`, wird dieser eine Test umgedreht.
>   - Ergebnis: 15 grün, 1 `[Ignore]` (siehe Befund). Das ganze Testprojekt lief zweimal hintereinander mit 17 grün und 1 ignoriert. Seit `ac27bd0` 17 SSH-Tests, alle grün (der ignorierte ist wieder an, dazu sein WS-Zwilling).
>   - **Mutationen:** 22, ein Testprozess je Lauf, die Quellen danach zurückgesetzt. 20 werden rot, in Hermod, WWCP_Core, WWCP_OCPP, WWCP_Node, LC und CS.
>   - Grün bleiben zwei, beide aus Verteidigung in der Tiefe: Eine Station, die forwarden darf, findet auf dem Node nichts zum Forwarden, und eine, die ein Terminal bekäme, verlangt keins. Werden beide Forwarding-Sperren zugleich aufgehoben, werden die Forwarding-Asserts rot.
>   - Exec und SFTP einer Station hängen daran, was der Node einer Station gar nicht anbietet: kein Exec, SFTP nur als Sicht eines Kontos. Keine Mutation hebt das auf.
> - **Befund, behoben (2026-11-09, auf Achims Wunsch; WWCP_OCPP `ef49eba6` und EVChargingTestEnvironment `ac27bd0`, beide auf master, gepusht 2026-11-09 auf GitHub, git1 und git2):** Antworten auf Anfragen, die ein LC nach oben weiterleitet, gingen im LC verloren, über SSH wie über WebSocket.
>   - Im Standard-Networking kommt die Antwort des CSMS über die Client-Verbindung des LC. `OCPPWebSocketAdapterIN` adressierte sie dort an den LC selbst, denn nur der Server-Zweig fragte `FORWARD.GetForwardedNodeId` (JSON und binär, 2.1 und 1.6). Die Station bekam keine Antwort auf ihren BootNotification und fragte nach 60 s wieder. So war es seit WWCP_OCPP `7da54995` (2024-08-10), kein Rückschritt durch 5.3.
>   - **Fix, Teil 1:** Beide Verbindungsrollen fragen jetzt `GetForwardedNodeId`.
>   - **Fix, Teil 2, Request-Ids:** Jeder Knoten zählt seine Requests vom selben Start (900001 bzw. 800001). Zwei Stationen hinter einem LC und der LC selbst fragen also oft mit denselben Ids, und `expectedResponses` hielt einen Eintrag je Id.
>     - Ein weitergeleiteter Request geht jetzt unter einer zufälligen eigenen Id des LC weiter (`ForwardUnderAnIdOfItsOwn`, 30 Zeichen, nie eine der Zahlen eigener Requests). Die Antwort geht unter der ursprünglichen Id zurück (`ChangeRequestId` an den JSON- und Binär-Request- und -Response-Nachrichten).
>     - Signaturen decken die Payload, nicht die Id des Frames.
>   - **Tests:**
>     - `ForwardingUpInStandardModeTests` in WWCP_OCPP, 2.1 (3) und 1.6 (2): zwei Stationen mit einer Id; der eigene Request des LC neben einem weitergeleiteten mit derselben Id; in 2.1 binär. Der CSMS antwortet erst, wenn der LC beide geschickt hat. Vor dem Fix rot, danach grün.
>     - In EVChargingTestEnvironment ist `AStationsRequest_ThroughTheController_IsAnsweredByTheCSMS` wieder an (SSH: Boot und `BinaryDataTransfer`), dazu der Zwilling mit WS-Station.
>     - 9 Mutationen des Fixes, alle rot. v2.1 2014/2014, v1.6 650/650, Node 166/166, EVChargingTestEnvironmentTests 19/19.
>   - Die übrigen SSH-Tests lassen den LC weiter selbst für `CSMS` antworten (Anycast), damit sie beim SSH-Abschnitt bleiben.
>   - Keine CLI (LocalControllerCLI, CSMSCLI, GatewayCLI) umgeht den Fehler; LocalController wählt seinen CSMS im Standard-Networking.
> - **Neue Befunde dazu, behoben (2026-11-09, auf Achims Wunsch; WWCP_OCPP `79f39610` und `e8ebaf97` auf `a06dc241`, EVChargingTestEnvironment `6264095`, alle auf master, gepusht 2026-11-09 auf GitHub, git1 und git2):**
>   - `TestLocalControllerNode` leitete nur Requests mit eigenem Filter weiter. Heartbeat, StatusNotification usw. bekamen vom LC „Filtered“, auch hinter dem LocalController-Produkt, das diesen Knoten nutzt.
>     - **Fix `79f39610`:** `ALocalControllerNode` setzt FORWARDs Default-Entscheidung auf FORWARD (FORWARDs eigener Default ist DROP). Die Filter von `TestLocalControllerNode` entscheiden weiter, was sie entscheiden.
>   - Request- und Response-Errors gingen gar nicht zurück: `OCPPWebSocketAdapterIN` nahm jeden als eigenen. FORWARDs Handler dafür rief niemand auf, und sie reichten nur zu spät gekommene weiter (`Timeout <= Now`).
>     - **Fix `e8ebaf97`, 2.1 und 1.6, JSON und binär:** Errors gehen jetzt den Weg der Antworten. IN adressiert einen Error im Standard-Networking an den Fragenden, wenn der Knoten den Request weitergeleitet hat, und gibt ihn an FORWARD. FORWARD schickt ihn rechtzeitig weiter, unter der ursprünglichen Id (`ChangeRequestId` an den vier Error-Nachrichten, `ChangeNetworking` an den zwei Response-Errors). Alle anderen Errors bleiben die eigenen des Knotens.
>   - **Tests** (`ForwardingUpInStandardModeTests`): in 2.1 Heartbeat plus StatusNotification durch den LC, ein Request- und ein Response-Error auf einen weitergeleiteten Request, ein Request-Error auf einen weitergeleiteten binären Request; in 1.6 ein Request- und ein Response-Error. Auf dem alten Stand alle rot, aus dem richtigen Grund (Filtered, Timeout oder die späte Antwort des CSMS statt des Errors), danach grün.
>   - **Baseline** auf `a06dc241` (`ef49eba6` plus zwei Testcommits von origin): v2.1 2014/2014, v1.6 650/650, Node 166/166, alles grün. Danach v2.1 2018/2018, v1.6 652/652, Node 166/166.
>   - **Mutationen:** 16, alle rot, jeder benannte Test in jedem Lauf. Default DROP (2.1-Test und die E2E-Kette); je JSON-Request- und Response-Error in 2.1: als eigener genommen, nicht adressiert, nur zu spät weiter, unter der weitergeleiteten Id zurück (8); fünf davon in 1.6; `ChangeRequestId` und `ChangeNetworking`, die nichts ändern (2).
>   - **E2E `6264095`:** Die Kettentests schicken jetzt auch Heartbeat und StatusNotification durch den LC, über SSH und über WebSocket. Der CSMS beantwortet beide. 37/37.
>   - **Gepinnt in LocalControllerCLI `9d70083`** auf `0208119` (2026-11-09, auf Achims Wunsch; gepusht 2026-11-09 auf GitHub, git1 und git2): WWCP_OCPP `f88842f4` → `e8ebaf97`, dazu WWCP_Core `fe46c384` → `4920c0b9`, weil `c21aa445` dessen `8b77c0c6` braucht. Das Produkt baut seinen Knoten auf `TestLocalControllerNode : ALocalControllerNode` und setzt kein eigenes Forwarding, die Fixes greifen also dort. Gegen denselben Lauf auf den alten Pins: LocalControllerTests 629/629 (629), v2.1 2018/2018 (2010 plus die acht neuen Tests), WWCP_Core 104/104 (102), WWCP_Node 1406/1406 (1406). 4 Smoke-Starts ohne Fehler, Banner „built from“ mit beiden neuen SHAs.
> - **Weitere Befunde dabei (an Achim, nicht behoben):**
>   - Binäre Request- und Response-Errors kommen nicht als das an, was sie sind. Ihre Binär-Parser sind auskommentiert, und `ToByteArray` schreibt JSON. Ein binärer Response-Error des CSMS kam beim LC als binäre Response an und ging so zur Station („OK“). Die binären Hälften des Fixes sind deshalb ungetestet.
>   - 1.6: Einen Request-Error, den ein Knoten für einen unlesbaren Request baut, adressiert IN an niemanden, und er wird nie gesendet. 2.1 hat dafür `AddressToSender`. Die 1.6-Tests schicken ihren Request-Error deshalb selbst.
>   - `Result.FromSendRequestState` liest nur Request-Errors. Wer einen Response-Error bekommt, sieht `GenericError` ohne Text.
>   - OCPP 2.1s CALLRESULTERROR geht vom Fragenden zum Antwortenden. Die Bibliothek nimmt einen Response-Error als Nachricht des Antwortenden an den Fragenden, und der Fix folgt ihr darin.
>   - 1.6 `BinaryDataTransfer` ist nicht implementiert: eingehend `NotImplementedException`, ausgehend großteils auskommentiert.
>   - FORWARD zählt jeden weitergeleiteten Request zusätzlich als verworfen, denn nach dem FORWARD-Zweig läuft die REPLACE/REJECT/DROP-Kette mit. Ein REJECT ohne Reject-Response wird still verworfen.
> - **Beobachtung:** Eine `ocpp@`-Anfrage, die eine AccessRule verweigert, nimmt die Station nicht als endgültig. Sie versucht es mit Backoff weiter (2, 4, 7, 18 s …), obwohl `DialOverSSH` „the OCPP subsystem refused“ zu den endgültigen Antworten zählt. `IsFinal` kennt nur `SshAuthenticationException` und `SshMessageRefusedException`. Der Test prüft nur, dass die Station nicht wieder hereinkommt.
> - **CSMS über SSH (5.7), 2026-11-09, auf Achims Wunsch (EVChargingTestEnvironment `ae70739` und `6275220` auf master, gepusht 2026-11-09 auf GitHub, git1 und git2):** Eine echte ChargingStation wählt einen echten CSMS direkt per `ssh://cs001@127.0.0.1:<port>`, ohne LC dazwischen.
>   - **Pin:** CSMS `41fbc7d` → `9a50ec6`. Er baut mit WWCP_OCPP `ef49eba6`, sonst bewegt sich nichts. 19/19 wie zuvor.
>   - **Aufbau:** `OCPPOverSSHTests` ist jetzt die abstrakte, gemeinsame Basis mit der Station, dem Hermod-`SshClient` und 15 Tests. `LocalControllerOverSSHTests` und `CSMSOverSSHTests` sagen je, was ihr Server ist. Fünf Testnamen sagen jetzt „Server“ statt „Controller“.
>   - **Beide Server** bestehen dieselben 15 Tests: die oben aufgezählten ohne die Kette.
>   - **Nur der CSMS:** eine Station wird abgeschaltet; ihre Login-Gruppe nimmt keine SSH-Keys mehr; `ocppServer.ssh.enabled = false` zur Laufzeit. Jedes Mal endet die Session sofort, und die Station wird beim Wiederkommen schon am SSH-Login abgewiesen. Eine andere Station bleibt verbunden. Wieder `true`: eine Station kommt ohne Neustart herein.
>   - **Ergebnis:** 37/37 (LC 17, CSMS 18, OCPI-Peering 2).
>   - **Mutationen:** 33, ein Testprozess je Fixture und Lauf, die Quellen danach zurückgesetzt.
>     - Die 16 gemeinsamen der ersten Runde (Hermod, WWCP_Core, WWCP_OCPP, WWCP_Node, CS) werden für beide Server rot, die 4 des LC wieder rot.
>     - 13 im CSMS, 11 rot. „Jeder Key einer bekannten Station“ lässt den Test des entzogenen Keys grün: ohne ihren einzigen Key ist die Station gar kein SSH-Login mehr (`StationSSHSignIns.Knows`). Der Test des fremden Keys wird rot. „SFTP für eine Station“ bleibt grün, weil der Node SFTP nur als Sicht eines Kontos anbietet (wie beim LC).
> - **Commissioning über SSH (5.6.4), 2026-11-09, auf Achims Wunsch (EVChargingTestEnvironment `549eae9` auf `6264095`, gepusht 2026-11-09 auf GitHub, git1 und git2):** Ein Werkzeug spricht OCPP 2.1 mit einer echten Station auf deren eigenem SSH-Server, angemeldet als Konto der Station mit dessen Key. Das Werkzeug ist ein schlichter Hermod-`SshMessageClient`.
>   - **Pin:** ChargingStation `6acc6eb` → `4b36729` (`3b60262` dazwischen ändert nur das Frontend-Lockfile), sonst bewegt sich nichts.
>   - **`CommissioningOverSSHTests` (10):**
>     - Das Werkzeug eines Installers wird vom 2.1-Knoten der Station beantwortet, unter dem Namen des Kontos; der SSH-Server der Station sagt, wofür die Session ist.
>     - Ein echter CSMS am Uplink, per SSH und per WebSocket: Eine BootNotification, um die das Werkzeug bittet, geht an den CSMS. Was der CSMS fragt, wird ihm beantwortet, und den Heartbeat der Station beantwortet er. Das Werkzeug bekommt nur seine eigenen Antworten. Nachdem es weg ist, erreicht der CSMS die Station weiter und die Station den CSMS (der Fall hinter 7.3).
>     - Installer und Systemadministrator bekommen das Subsystem, cpo und viewer nicht, jeweils als eigenes Konto mit eigenem Key.
>     - Abgewiesen werden ein HELLO, das den CSMS, die Station oder eine andere Node-Id als das Konto nennt, und ein Konto „csms“; der Uplink arbeitet danach weiter.
>     - Nur `ocpp1.6` angeboten: `unsupported-subprotocol` mit dem, was gesprochen wird; `ocpp1.6` und `ocpp2.0.1` angeboten: `ocpp2.0.1`.
>     - Aus, wo die Datei nichts sagt. Per HTTP-`PUT /api/v1/configuration/commissioning` (root mit seinem erzeugten Passwort) aus: Das Werkzeug wird sofort getrennt, und die Datei sagt es; wieder an: Ein Werkzeug kommt ohne Neustart herein.
>     - SSH-Server der Station zur Laufzeit aus: Das Werkzeug wird getrennt, keiner kommt herein; wieder an: Das Subsystem ist am neuen Server da. Startet die Station ohne SSH-Server, nennt Commissioning keine URL und das Log sagt es.
>   - **Ergebnis:** 47/47 (Commissioning 10, LC 17, CSMS 18, OCPI-Peering 2).
>   - **Mutationen:** 17, ein Testprozess je Lauf, die Quellen danach zurückgesetzt, 16 rot.
>     - ChargingStation 12: CSMS nicht als eigene Anycast-Id, Login-Name nicht geprüft, jedes HELLO angenommen, das Werkzeug unter dem Namen des CSMS (die Route aus 7.3; beide Uplink-Tests rot), Lesen reicht fürs Subsystem, Abschalten lässt das Subsystem stehen, Schalter nicht in die Datei, keine Warnung bei SSH aus, beim Start nicht bedient, bedient ohne Eintrag, PUT nimmt nicht, was gesendet wurde. Grün bleibt „URL auch bei SSH aus“: `SSHURL` ist dann ohnehin null, die Mutation ist gleichwertig.
>     - WWCP_Node 3: Recht des Subsystems nicht gefragt; ein entferntes Subsystem beendet keine Session (erst rot, nachdem der Test die 5-s-Neuprüfung des Knotens auf 10 min setzt, sonst trennt diese das Werkzeug nach bis zu 5 s); SSH-Server läuft nach dem Abschalten weiter.
>     - WWCP_Core 1: Ein Login darf als jede Node-Id auftreten, die sein HELLO nennt. Hermod 1: Keine Abweisung, wenn kein angebotenes Subprotokoll gesprochen wird.
>   - **Befund (an Achim, nicht behoben):** `TestChargingStationNode` (WWCP_OCPP v2.1) antwortet auf `TriggerMessage` mit `Heartbeat` „Rejected“, mit dem Kommentar „Seems not to be allowed any more!“. OCPP 2.0.1 und 2.1 führen `Heartbeat` aber in `MessageTriggerEnumType`. Die Tests bitten deshalb um eine BootNotification.
> - **Nicht abgedeckt:**
>   - auf dem Weg Station → LC → CSMS alles außer BootNotification, `BinaryDataTransfer`, Heartbeat und StatusNotification
>   - ein zu großes Frame vom LC zur Station
>   - binäre SENDs: 2.1 sendet keine von sich aus; dafür gibt es `BinarySendMessageTests` in WWCP_OCPP
>   - PING/PONG und eine Verbindung, die ohne Wort abreißt
>   - `from=`/`expiry-time=` (das prüfen die LC-Tests)
>   - `wwcp@` und OCPP 1.6 über SSH
>   - beim Commissioning: ein Werkzeug an einer Station hinter einem LC, ein Knoten, der neu gebaut wird (das prüft `CommissioningOverSSHTests` der Station), und ein Konto, das wie die Station heißt
>   - die Grenzen je Principal-Art (das prüfen die WWCP_Node-Tests)

---

## 6. Reihenfolge

1. ~~Hermod-Fixes mergen.~~ Erledigt.
2. ~~Hermod 5.1 (nicht brechend).~~ Erledigt.
3. **Parallel:**
   - WWCP_Node 5.4 (AccessRules, Composite-Auth, Subsystem-Haken); braucht nur 5.1.2 und 5.1.3.
   - LC-Stores 5.5.2 und CS-Key/known_hosts 5.6.1–5.6.2; brauchen keine neuen Pins.
4. WWCP_Core 5.2 und WWCP_OCPP 5.3 im Gleichschritt, angekündigt, in einem kurzen Fenster.
5. Verbraucher-Anpassungen und Pin-Bumps; LC 5.5 und CS 5.6 fertigstellen.
6. E2E 5.8.
7. CSMS 5.7, CS als Server 5.6.4.
8. Später: SSH-CA, LC-Uplink über SSH, Profilwechsel per `SetNetworkProfile`.

## 7. Offene Punkte

1. ~~Subprotokoll-IDs für `wwcp@`~~ – **entschieden (2026-11-06):** Es bleibt bei `wwcp@` und `ocpp@`, eine eigene Versions-ID wie `wwcp0.1` gibt es nicht.
   - Die Subprotokoll-Liste im HELLO ist deshalb **optional**. Ist sie leer, wählt der Server keines aus, und WELCOME nennt keins.
   - Für `ocpp@` bleiben `ocpp1.6`/`ocpp2.0.1`/`ocpp2.1` nötig, weil ein Server mehrere OCPP-Versionen bedient.
2. **Defaults der Nachrichtengrenzen:** die des WS-Servers übernehmen. Zu prüfen ist, welche Werte LC und CSMS dort heute setzen.
   - **Geprüft (2026-11-08, Pins wie in 5.8):** Sie sind **nicht** dieselben.
   - **WebSocket:** Weder LC noch CSMS setzen eine Grenze (`AttachWebSocketServer` ohne `MaxText…`/`MaxBinary…`), es gelten Hermods Defaults: eingehend 64 MiB für Text und Binär (`WebSocketFrame.DefaultMaxPayloadSize`, im Server `AWebSocketEndpoint` wie im Client `WebSocketClient`), ausgehend keine (`Max…MessageSizeOut` = `null`).
   - **SSH:** LC `ocppServer.ssh.maxMessageSize`, Default 16 MiB (= Hermods `SshMessageFraming.DefaultMaxMessageSize`), erlaubt 64 KiB–64 MiB, gilt ein- **und** ausgehend. Die Station (Hermods `SshMessageClient`) hat ebenso 16 MiB in beide Richtungen. WELCOME nennt dem Client die Grenze des Servers. Der CSMS hat `ocppServer.ssh` noch nicht (5.7).
   - Eine Nachricht zwischen 16 und 64 MiB geht also über WebSocket durch und über SSH nicht. Ausgehend hat nur SSH überhaupt eine Grenze.
   - **Offen (Achim):** den SSH-Default auf 64 MiB heben, oder bei 16 MiB bleiben und den WebSocket-Servern von LC und CSMS ebenfalls 16 MiB geben.
3. ~~**Commissioning-Route auf der CS** (5.6.4)~~ – **entschieden (2026-11-09):** eine eigene Node-Id, das Konto; das Werkzeug tritt nicht als `CSMS` auf. Begründung in 5.6, Stand 2026-11-09.
4. ~~`ConnectOCPPClient(URL)`~~ – **entschieden (2026-11-06):** `ConnectOCPPClient(URL)` wird der gemeinsame Einstieg und verzweigt nach Schema (`ws`/`wss` → WebSocket, `ssh` → SSH). Die bisherigen `ConnectOCPPWebSocketClient`-Aufrufe in LC, CSMS und CS wandern darauf.

## 8. Nebenbefunde

- **Erledigt**, auf Hermod master:
  - `d2ab407a`: `force-command` gilt jetzt auch für Subsysteme.
  - `6abdb089`: SFTP-Pakete höchstens 256 KiB; der Kanal wird bei Protokollfehlern geschlossen.
- **Erledigt**, auf WWCP_Node master, gepinnt in LocalControllerCLI `b64a969`:
  - `ba72874`: `sshKeys <account> remove SHA256:` nahm den einzigen Key eines Kontos, denn ein leerer Anfang trifft jeden Fingerprint. Jetzt wird das abgelehnt. `apiKeys` lehnte seine leeren Anfänge (`...`, `#`) schon ab; dafür gibt es jetzt einen Test.
- **Erledigt**, WWCP_OCPP `f88842f4` auf `7a22b512`, gepusht 2026-11-08, gepinnt in LocalControllerCLI `4937d55`:
  - `OCPP_BinarySendMessage` schrieb und erwartete das Typbyte 2 des CALL, im selben Layout. Jeder Empfänger versucht zuerst einen Request, also kam ein binärer SEND als Request an und wurde beantwortet.
  - Jetzt ist es 6, wie beim JSON-SEND.
  - Tests: `BinarySendMessageTests` (2), vorher rot. v2.1 2010/2010, v1.6 648/648, Node 166/166.
- **WWCP_OCPP v2.1:** `SetNetworkProfile` antwortet in `TestChargingStationNode` nur `Accepted` und wendet nichts an.
- **Erledigt**, Hermod `c85c8e9b` auf `ce2f06b8`, gepusht 2026-11-08, gepinnt in LocalControllerCLI `4937d55`:
  - Ein Key mit `force-command internal-sftp` (mit oder ohne Optionen) bekam bei Exec- oder Shell-Anfragen den Exec-Handler mit dem Befehl `internal-sftp`.
  - Jetzt antwortet Hermod wie sshd (`SUBSYSTEM_INT_SFTP_ERROR`): „This service allows sftp connections only.“, Exit-Status 1, Ablehnung im Audit. Das gilt mit und ohne Exec-Handler.
  - Tests: `ForceCommandSubsystemTests` (8 neue Fälle), 8 Mutationen rot, HermodTests 5553/5553.
