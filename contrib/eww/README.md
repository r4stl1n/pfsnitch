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
