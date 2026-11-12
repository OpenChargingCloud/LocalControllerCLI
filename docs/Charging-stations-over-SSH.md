# Charging stations over SSH: a walk-through

How to let a charging station speak OCPP to a local controller over SSH, from
both ends, in the order the steps are done. The same steps hold for a CSMS
(CSMSCLI), whose SSH port is 22351 where this page says 22350.

What the pieces are is in the READMEs: the server's side in
[LocalControllerCLI](../README.md#charging-stations-over-ssh) and
[LocalController](../libs/LocalController/README.md), the station's side under
*Connections* in the README of
[ChargingStation](https://github.com/OpenChargingCloud/ChargingStation).
[OCPP-over-SSH.md](OCPP-over-SSH.md) beside this page is the implementation
plan, not a manual.


## What it is

A station signs in to the controller's SSH server - the one that serves the
command line, port 22350 unless `--ssh-port` says otherwise - under its own
identification, with an SSH key of its own, and asks for the subsystem
`ocpp@open.charging.cloud`. There is no port of its own for it. Inside the
subsystem the station speaks the OCPP it would speak over a WebSocket.

The station gets OCPP and nothing else: no command line, no command, no SFTP.
The controller is believed by its SSH host key, as it would be by a TLS
certificate.


## The steps

### 1. On the controller: switch OCPP over SSH on

It is off unless somebody switches it on. Either the switch on the **Charging
stations** page of the web interface, or in `configuration.json`:

```json
"ocppServer": { "ssh": { "enabled": true } }
```

It takes effect at once, without a restart, and only while the charging
station server itself (`ocppServer.enabled`) and the SSH server run. The
banner then shows where the stations connect - here with one station already
given a key - and the host key they pin is the one under `SSH`:

```
  stations       ws://0.0.0.0:2351 (unencrypted), 1 login(s)
                 ssh://127.0.0.1:22350
                 subsystem ocpp@open.charging.cloud, 1 with an SSH key
```

The SSH server listens on the loopback unless the controller was started with
`--any`: a station on another machine needs `--any`. The address shown is the
SSH server's own, or the first name in `reachableAs`.

### 2. On the station: write the connection down

On the station's **Connections** page (`/configuration/connections`), add a
connection with the controller's address as an `ssh://` URL:

```
ssh://CS001@lc.example.org:22350
```

The login in front of the `@` is the name the station signs in under. It must
be the station's identification exactly as the controller lists it (step 3).
Without
a login in the URL the station signs in as the login of the HTTP Basic
credentials the connection names, or else as the name of the OCPP node that
dials.

The first time an `ssh://` connection is written down, tested or dialled, the
station makes an Ed25519 key pair of its own and keeps it in
`ocpp-connections/ssh/`. The page shows the public half as one line:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... cs001
```

Copy that line. A TLS client certificate and a TOTP password are refused over
SSH.

### 3. On the controller: give the station its key

Under **Logins and groups** in the web interface, or with `stationKeys` - at
the console, or over SSH by an account that may change the charging stations:

```
stationKeys CS001 add ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... cs001
```

A station that is not listed yet is added by this, in the group `default`.
The answer says what happened, and beside it anything that still keeps the
station out:

```
'CS001' is a charging station of this local controller now, in the group 'default', and signs in over SSH with the key SHA256:....
```

One key is one charging station. `stationKeys` lists every station's keys,
`stationKeys CS001` one station's, and `stationKeys CS001 remove SHA256:abc`
takes a key away - by the fingerprint listed, or enough of its beginning -
and ends the session that key opened at once.

### 4. On the station: pin the controller's host key

Beside the connection, write the controller's host key: its fingerprint
(`SHA256:...`) or its public-key line. The controller's banner prints the
fingerprint under `SSH`.

Left empty, the station believes the first server that answers and writes the
key it showed down; from then on that key is the only one taken. Pin it by
hand wherever the first connection crosses a network you do not trust.

### 5. Test, then let it connect

The connection test on the station's page says which host key the server
showed, and writes nothing down. After that the page shows where the
connection stands:

| | |
|---|---|
| connected   | since when |
| refused     | a host key not believed, or an SSH login not taken - not tried again |
| not reached | not connected since the start, tried again by itself |

On the controller, `stationKeys CS001` shows the key, and the banner counts
the stations with an SSH key.


## What lets a station in

All of these, asked at sign-in and again every few seconds while the session
lasts:

- OCPP over SSH is switched on, and the SSH server runs.
- The station is listed and switched on.
- The key is one of the station's, switched on, and not expired.
- The station's login group is switched on and accepts SSH keys (`sshkey`
  among its sign-in methods).

When one of them stops holding - a key taken away, the station or its group
switched off, OCPP over SSH switched off - the session ends at once.

The group `default` accepts SSH keys, unless it was written to the file
before SSH keys existed: such a group stays as the file says until somebody
adds `sshkey` under **Logins and groups**. A group's OCPP security profiles
are not asked over SSH.


## Restricting a key

A key is a line of an `authorized_keys` file, and the options in front of it
hold:

```
stationKeys CS001 add from="10.20.0.0/16",expiry-time="20271231" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... cs001
```

| Option | What it does |
|---|---|
| `from="10.20.0.0/16,192.0.2.7"` | the station may sign in from these addresses or networks only. Addresses and CIDR blocks; a host name pattern or a negation is refused when the key is given. |
| `expiry-time="20271231"` | the key lets nobody in after that time: `YYYYMMDD[HHMM[SS]][Z]` or ISO 8601. `not-after=` is the same. |
| `not-before="20270101"` | the key lets nobody in before that time. |

Write the options without spaces between them, as above.


## Restricting all stations at once

The SSH server's access rules apply to stations as to accounts. A station is
the principal `station:<id>`, its login group `group:<name>`, and OCPP over
SSH the service `subsystem:ocpp@open.charging.cloud`. The first rule that
matches decides; `allow` passes a session on to everything above, it never
lets in what that would not.

Stations from one network only:

```
sshAccessRules add allow principal=station:* source=10.20.0.0/16
sshAccessRules add deny principal=station:* # stations come from the charging network only
```

Before relying on a rule, ask which one decides:

```
sshAccessRules test station:CS001 service=subsystem:ocpp@open.charging.cloud source=10.20.0.5
```

Changes are in effect at once, and every open session is asked again.


## The settings

All under `ocppServer.ssh` in `configuration.json` of the local controller:

| Field | Default | |
|---|---|---|
| `enabled` | `false` | whether stations may connect over SSH. In effect at once. |
| `subprotocols` | those of the WebSocket port | the OCPP versions offered over SSH, of `ocpp1.6`, `ocpp2.0.1`, `ocpp2.1`. Next start. |
| `maxMessageSize` | `67108864` (64 MiB) | the largest OCPP message taken and sent, in bytes; 65536 to 67108864. Next start. |
| `pingEverySeconds` | `30` | how often a connection is pinged, which is how a station that went away is noticed; 5 to 3600. Next start. |

```json
"ocppServer": {
  "ssh": {
    "enabled": true,
    "subprotocols": [ "ocpp2.1" ],
    "maxMessageSize": 16777216,
    "pingEverySeconds": 30
  }
}
```

The port, and whether the SSH server runs at all, are the `ssh` section's
(`--ssh-port`, `--no-ssh`).


## When it does not connect

Start with `stationKeys CS001` on the controller: it says beside the key
whatever keeps the station out. The controller's log says why a station's own
key was refused, once a minute at most; a key it does not know is only the
SSH server's line of a failed sign-in.

| What you see | What it means | What to do |
|---|---|---|
| `OCPP over SSH is switched off: no charging station signs in over SSH.` | step 1 was not done, or the station server is off | switch it on |
| `The SSH server of this local controller is off: ...` | started with `--no-ssh`, or switched off | switch the SSH server on |
| `'CS001' is switched off: no key lets it in.` | the station's login is switched off | switch it on under **Logins and groups** |
| `The group 'x' of 'CS001' is switched off: ...` | its login group is switched off | switch the group on |
| `The group 'x' of 'CS001' does not accept SSH keys: ...` | the group lacks `sshkey` | add SSH keys to the group's sign-in methods |
| `'CS001' has no SSH key.` or `'CS001' is no charging station of this local controller.` | step 3 was not done, or under another name | `stationKeys CS001 add ...` |
| the station says *refused*, the controller logs a failed sign-in | the login in the URL is not the station's identification here, or the key is not the one given | compare the URL's login with `stationKeys`, and the fingerprints |
| the station says *refused* with a host key not believed | the controller shows another host key than the one pinned | compare with the fingerprint under `SSH` in the banner; correct the pin only if the change is yours |
| the station says *not reached* | nothing answers at that address | the controller listens on the loopback unless started with `--any`; check the port |
| it worked, and stopped | the key expired, or `from=` no longer matches the station's address | `stationKeys CS001` shows the options of each key |
