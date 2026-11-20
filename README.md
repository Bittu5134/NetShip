# netship

Watches this machine's outbound connections and stays quiet until something is
new for the binary making them.

It is not a connection log. It remembers, per executable, every remote endpoint
that binary has ever been seen talking to, and then only speaks up when
something it has never seen before happens:

```
HIGH    install.js (pid 4412, npm -> node)
        Download-and-execute shaped command line
        · first ever outbound connection: 203.0.113.9:443 · NL · Unmanaged Ltd
        · runs from a temporary directory · runs from a package install directory

LOW     firefox (pid 2210)
        New destination for firefox: 192.0.2.51:443 · BR · Claro NXT Telecom
        · baseline for this executable goes back to an earlier session
```

No root, no agent, no account, no flags. One binary and a five line JSON file.

## run

```bash
go build -o netship.bin .    # Go 1.26+
./netship.bin
```

```
netship - what is new on this machine's network edge

  dashboard  http://127.0.0.1:8787
  config     ~/.config/netship/config.json
  baseline   ~/.local/share/netship (0 binaries)
  poll       every 2s, silent for the first 5m
```

Open the URL. Start and Stop control the watcher. Demo puts a synthetic case
list in front of you without touching this machine: three made up cases on
documentation addresses, with a banner saying so.

The first `learning` window is silent because it is filling the baseline, not
because it is broken. Quiet after that is also normal. An empty case list is
the healthy state on a laptop.

## config

`~/.config/netship/config.json`, written on first run:

```json
{
  "listen": "127.0.0.1:8787",
  "data_dir": "~/.local/share/netship",
  "interval": "2s",
  "learning": "5m",
  "enrich": true
}
```

Missing fields stay default, so a partial file is fine. `enrich: false` turns
off the ASN lookups and the tool still works, it just stops knowing which
destinations are cloud infrastructure.

To forget everything it has learned:

```bash
rm ~/.local/share/netship/baseline.json
```

Uninstalling is deleting the binary.

## why it exists

Every network monitor I tried died the same way: it showed me everything and I
read nothing. One minute of ordinary desktop use produced 356 rows, 70 of them
sockets that had already closed and 69 with no owning process, and not one
finding, while scoring a torrent client 20/100 for being busy.

So this stores state instead of events: one row per binary and remote, one card
per process, and output only when the pair is new. A browser talking to Fastly
is not a finding. Dropping cloud and CDN traffic before it is stored removes
most of the noise, and the suppressed counter in the dashboard is the number
that got thrown away, so the filter is visible instead of invisible.

## how it works

1. Poll the socket table every `interval`, skipping itself, sockets with no
   owner, loopback and private addresses, and teardown states.
2. Name each socket's process and key it on executable plus start time, so a
   browser restarted forty times is one subject.
3. Look up each remote's ASN over plain DNS (Team Cymru). No HTTP, no key, no
   third party learning what you resolve. Cloud and CDN ASNs stop here.
4. Compare what is left against `baseline.json`.
5. Report the difference, on stdout and in the dashboard.

## findings

| kind | severity | when |
|---|---|---|
| `SUSPICIOUS_CMD` | high | the command line looks like download and execute: `curl ... \| sh`, `base64 -d`, `/dev/tcp/`, `nc -e` |
| `FIRST_NETWORK` | medium, high if the origin is bad | an executable with no baseline makes its first outbound connection |
| `NEW_DESTINATION` | low, medium from a bad origin | a known binary talks to a non cloud endpoint it has never used |
| `RISKY_ORIGIN` | medium | something from `/tmp`, `Downloads`, `node_modules`, or a binary written in the last day goes out |
| `NEW_LISTENER` | low | a new binary binds a port, or any port from a bad origin |
| `FANOUT` | medium | one process reaches 8 or more new destinations inside a minute |

Severity comes from combining facts about the same process, not from adding
points until a number looks scary.

## what it cannot do

- Short-lived processes are invisible. At 2s polling a `curl` that lives 300ms
  is usually missed, and if it exits before attribution there is nothing to
  name.
- No byte counters, so no volume or exfiltration detection. The socket table
  does not have them.
- No names and no payload. IPs only, no SNI, no DNS sniffing.
- Without root it sees your processes only.
- Whatever was already running before the first scan is normal. Delete
  `baseline.json` if you think that happened.
- Anything that wants to kill it can.

## known issues

- The map draws every flow on the same canvas, so a few hundred destinations
  is fine and a few thousand is not.
- Restarting with a big baseline takes a moment to load before the dashboard
  has anything to show.
- The demo store is seeded on first use and thrown away on exit, so charts in
  demo mode always start at the same place.

## layout

`main.go` is the shell: config, listener, signal handling. Everything else is
the `netship` package, including the dashboard, which is embedded and has no
build step.
