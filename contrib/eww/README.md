# eww frontend

The desktop widget: a bar chip, a rule-management panel, the connection prompt,
and a binary-details window.

This is **one** frontend, not a requirement — pfsnitch has no idea it exists.
Everything here is built on `pfsnitch apps --json`, `pfsnitch rules --json` and
the documented prompt contract, so it is also a worked example of building your
own. See [../../docs/FRONTENDS.md](../../docs/FRONTENDS.md).

## Install

```sh
cp scripts/pfsnitch-* ~/.config/eww/scripts/
chmod 755 ~/.config/eww/scripts/pfsnitch-*
cat widgets.yuck >> ~/.config/eww/eww.yuck
cat widgets.scss >> ~/.config/eww/eww.scss
```

Then add the chip to your bar:

```lisp
(w_snitch)
```

and reload: `eww reload`.

## What needs privileges

Listing rules does not — the policy file is world-readable. Changing them does:
the panel's buttons call `doas -n pfsnitch ...`, so the desktop user needs a
`doas.conf` entry permitting that without a password. Without one the panel
still renders correctly, it just cannot alter anything.

## Notes for anyone editing this

- `eww reload` **silently keeps the last-good config** on a parse error. A clean
  reload proves nothing; check that a variable you just added actually exists
  (`eww get <name>`) before believing it took.
- `:visible` is not reliably re-applied to a widget after it is built. Use a
  `revealer` with `:reveal` for anything that toggles.
- The catch-all rule group's key is the **empty string**, so a variable
  defaulting to `""` will silently match it. `snitch_open` uses a `::none::`
  sentinel for this reason.
- Nerd-font glyphs do not survive being piped through a shell heredoc, and
  `perl -pi` with a `\x{...}` replacement re-encodes the *whole file*. Use `sed`
  with bytes from `printf`, under `LC_ALL=C`.

## A trap worth naming

Do not edit these files with `perl -pi -e 's/.../.../'`. Perl interprets the
*replacement* side: a `${g.deny}` becomes a variable dereference and silently
substitutes nothing, and a `\x{f00d}` re-encodes the entire file. Both have
happened here, and both produced widgets that looked fine until someone noticed
a missing number. Use `sed`, which does not interpolate, and pass glyph bytes
in via `printf` under `LC_ALL=C`.

## eww loses track of its windows

On this machine eww 0.5.0 desyncs its window registry from what is actually on
screen:

- `eww active-windows` stops listing a window - sometimes the bar, sometimes
  everything - while that window is still displayed
- `eww close` then answers "no such window was open" for a panel you are
  looking at, so it cannot be dismissed. This is the "the X does nothing" bug.

The daemon is **healthy** while this happens. It answers `ping`, the GTK main
loop is still running, and the clock in the bar keeps ticking - verified by
comparing screenshots 65 seconds apart. So this is a bookkeeping fault, not a
crash, and restarting on it is a big hammer.

Bisecting the panel found no single widget at fault: header, `for` loop,
`scroll`, `revealer`, buttons and tooltips each survive open/close/open alone,
and only the whole panel does not. Slowing the polls to 60s, removing every
tooltip, and changing `:stacking` and `:focusable` changed nothing.

Two mitigations, each aimed at the symptom it can actually see:

- `scripts/pfsnitch-close-panel` backs the panel's close button. If eww refuses
  the close AND has also lost the bar from its registry - the desync signature,
  as opposed to an ordinary second click on a closed panel - it restarts eww,
  because nothing short of that destroys an orphaned surface.
- `scripts/eww-watchdog` restarts eww only when it becomes genuinely
  unreachable. An earlier version restarted whenever the bar vanished from the
  registry, which tore down a perfectly healthy bar every time the registry
  desynced.

```
exec-once = daemon -f -P /tmp/eww-watchdog.pid ~/.config/eww/scripts/eww-watchdog
```
