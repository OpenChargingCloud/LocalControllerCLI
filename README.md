# Local Controller

[![CI](https://github.com/OpenChargingCloud/LocalControllerCLI/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenChargingCloud/LocalControllerCLI/actions/workflows/ci.yml)
[![Nightly](https://github.com/OpenChargingCloud/LocalControllerCLI/actions/workflows/nightly.yml/badge.svg)](https://github.com/OpenChargingCloud/LocalControllerCLI/actions/workflows/nightly.yml)

This software implements an EV Charging Local Controller: the box between a
CSMS above and the charging stations below, with a web interface in front of
it. What it is and what it can be told lives in
[libs/LocalController](libs/LocalController); this repository is the command
line that starts it and the submodules it is built from.


### Getting it

The libraries it is built from are submodules, so they have to come along:

```
git clone --recurse-submodules <this repository>
```

If you already cloned it without them:

```
git submodule update --init --recursive
```

They are fetched from GitHub over https, so nothing but git is needed - no
account, no key.

**On Windows**, turn long paths on first:

```
git config --global core.longpaths true
```

The deepest file in the submodules is well over 140 characters below the clone
root, so under the classic 260-character limit the root has little room to live
in. `D:\src\LocalController` is fine; a checkout somewhere below
`C:\Users\<you>\AppData\Local\Temp\...` is not, and the clone fails halfway
through a submodule with `Filename too long` rather than at the start.
Per clone instead of globally: `git clone -c core.longpaths=true ...`.


### Building and running it

```
dotnet build LocalControllerCLI.slnx
dotnet run --project LocalControllerCLI
```

The build needs the .NET 10 SDK and Node.js: the web interface is built by npm
and embedded into the assembly, so the controller is one thing to deploy.

Nothing has to be installed globally beside those two, and nothing has to be
fetched by hand first. The TypeScript and SASS compilers the libraries pin are
installed by `npm ci` on the first build, and the OCPP stylesheets are compiled
by the build. The ISO 15118 repository is a submodule here, but nothing in this
solution builds any of it, so ISO's schemas are not needed.

At the first start there are no accounts, so the controller makes one up for
the user `root`, keeps it under `accounts/` beside the solution and prints the
password once. Signing in happens at Hermod's HTTPExt API, mounted under
`/ext`. Then open http://127.0.0.1:2350/ and sign in.

**Recommended for the first start: give `root` your own SSH key** with it, so
that you can type at the controller over SSH from the start - see
[Typing at it over SSH](#typing-at-it-over-ssh):

```
dotnet run --project LocalControllerCLI -- --authorize-ssh-key root=C:\Users\you\.ssh\id_ed25519.pub
```

Without it, the first start makes up a key pair for `root` and prints its
private key once, below the password.

`dotnet run --project LocalControllerCLI -- --help` lists the rest: `--port`,
`--any`, `--accounts <dir>`, `--frontend <dir>`, `--config <file>`,
`--verbose`, `--quiet`, `--no-trace`, `--log-file <dir>`, `--no-log-file`,
and the certificate store's `--certificates <dir>`,
`--import-certificate <kind>=<file>`, `--certificate-password <pw>` and
`--list-certificates`. They are every node's switches, read by WWCP_Node, as
is what the console says once the controller is up.


### The log

Everything that happens is written three times over, because the three answer
different questions. The **console** shows what is going on to whoever is
watching, at the level `--verbose` and `--quiet` choose. The **Logs** page
keeps the last two thousand entries for whoever asks, and loses them when the
process ends. And `logs/` beside the solution keeps one file per day, every
entry down to the debug ones, for the afternoon somebody asks what happened
last night - `--log-file <dir>` puts it elsewhere, `--no-log-file` leaves it
out, and nothing in it is ever deleted.

The days are UTC days, as the timestamps in the files are. A file that cannot
be written is said once on the console rather than once per entry, every entry
after that is tried again, and the first one that makes it is preceded by a
line saying how many are missing.


### Typing at it

Once it is up, the console is a prompt rather than a place that only scrolls:

```
LocalController> syncNTS
succeeded after 1648 ms: 4 of 4 server(s) answered (2 required), offset +989.4 ms, spread 1.9 ms
  ptbtime1.ptb.de  +988.8 ms, round trip 56.2 ms, key exchange new
  ptbtime2.ptb.de  +989.8 ms, round trip 56.3 ms, key exchange new
  ptbtime3.ptb.de  +988.9 ms, round trip 56.3 ms, key exchange new
  ptbtime4.ptb.de  +990.7 ms, round trip 56.2 ms, key exchange new
```

`help` lists what can be typed, `quit` leaves, **Tab** completes and **↑**
walks back through what was typed before. `syncNTS` is **Sync now** on the
**NTS** page, typed: the same group of time servers is asked, the same entries
go into the log, and the same result is left behind for the page and the
overview to show. The one entry that differs says who asked - the page names
the account that pressed the button, the prompt says it was somebody at the
command line. Neither of them steps the clock.

The log keeps writing while you type, from whichever thread did the thing it is
reporting, and your half-typed line survives it: the line is taken off the
screen, the entry is written whole, and the line comes back with the cursor
where it was.

Where there is no terminal - from a script, under a service manager, in CI, or
with the output going into a file or through `| tee` - there is no prompt, and
the controller runs until it is stopped, exactly as it did before.


### Typing at it over SSH

The same prompt is served over SSH, on port 22350 — twenty thousand above the
web interface's — and on the addresses the web interface listens on: the
loopback, or every address with `--any`. Nothing else is: no shell of the
machine, no files, no tunnels. `--ssh-port` moves it, `--no-ssh` switches it
off.

Whoever signs in is an account of the local controller, under its name, with a
key of its own. The first start makes `root`; give it your public key with
that very start - the way recommended:

```
dotnet run --project LocalControllerCLI -- --authorize-ssh-key root=C:\Users\you\.ssh\id_ed25519.pub
```

The private key then stays on your machine, and no console ever shows it.
A first start without `--authorize-ssh-key root=...` makes up a key pair for
`root` instead and prints its private key once, below the password in the
first-start box: save the lines from `-----BEGIN OPENSSH PRIVATE KEY-----` to
the END line as a file only you can read, and sign in with
`ssh -i <file> -p 22350 root@127.0.0.1`, or import the file in PuTTYgen for
PuTTY. Like the password it is kept nowhere - but a console may be kept, by a
service's journal or a redirected output; replace it with your own key and
take it out. `--authorize-ssh-key` also works at any later start.

An OpenSSH `.pub` goes in as it is, and so does what PuTTYgen saves with *Save
public key*. The key is kept in `accounts/ssh/root`, a file in the format of
`authorized_keys`, and putting a line into it by hand does the same; taking one
out locks that key out at once. Then:

```
ssh -p 22350 root@127.0.0.1
```

or, in PuTTY, host `127.0.0.1`, port `22350`, *Connection → Data → Auto-login
username* `root`, and the private key under *Connection → SSH → Auth →
Credentials*. The first time, PuTTY asks whether to trust the local
controller's host key: the banner prints its fingerprint under `SSH`, to
compare it with.

Everything works as at the console — Tab, the history, the log above the line
being typed — with three differences. `quit`, `exit` and Ctrl+D leave the
session, and the local controller keeps running. The account may do what its
roles let it do on the web interface, and the log names it: "'root' at the
command line over SSH asked this local controller to synchronise its time.",
tagged `cli` and `ssh`. And the session's log starts at the console's level and
is its own: `log debug` shows everything here, `log off` nothing, for this
session alone. `who` says who else is signed in.


### Your participation

This software is Open Source under the **Affero GPL 3.0 license**.
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to
request a feature or send us a pull request, feel free to use the normal
GitHub features to do so. For this please read the Contributor License
Agreement carefully and send us a signed copy or use a similar free and
open license.
