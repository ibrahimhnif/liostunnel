#!/usr/bin/env bash
#
# Proves the package would install what it claims, without installing it.
#
#     ./testing/verify-pkg.sh dist/LiosTunnel-abc1234.pkg
#
# `pkgutil --expand` unpacks the payload; nothing is run, nothing needs root.
set -uo pipefail
pkg="${1:-}"
[ -f "$pkg" ] || { echo "usage: $0 <package.pkg>"; exit 1; }
pass=0; fail=0
ok()  { echo "  PASS  $*"; pass=$((pass+1)); }
bad() { echo "  FAIL  $*"; fail=$((fail+1)); }

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
pkgutil --expand "$pkg" "$tmp/x" || { echo "cannot expand"; exit 1; }

# The payload is a cpio archive; extract it to look inside.
payload="$(find "$tmp/x" -name Payload | head -1)"
[ -n "$payload" ] || { echo "no Payload in the package"; exit 1; }
mkdir -p "$tmp/p" && (cd "$tmp/p" && tar xzf "$payload" 2>/dev/null || \
  (cd "$tmp/p" && cat "$payload" | gunzip -dc | cpio -i --quiet))

# An extraction that produced nothing would make every path assertion below
# vacuous: they would all report a missing file, and none of them would be
# reading the package. On macOS the payload is a gzip-compressed cpio archive
# and bsdtar reads it directly; the cpio branch is for a tar that cannot.
[ -n "$(ls -A "$tmp/p")" ] || { echo "the payload extracted to nothing"; exit 1; }

app="$tmp/p/Applications/liostunnel_app.app"
helper="$app/Contents/Resources/helper"

# Located, not assumed. A productbuild wrapper puts the component's
# PackageInfo one level down inside <component>.pkg/, and a hardcoded
# "$tmp/x/PackageInfo" would then fail a package that is perfectly correct for
# being wrapped. Everything else in this file already uses `find`.
pkginfo="$(find "$tmp/x" -name PackageInfo | head -1)"
[ -n "$pkginfo" ] || { echo "no PackageInfo in the package"; exit 1; }

# Where the payload lands is TWO facts and only one of them is in the payload.
# The cpio holds `Applications/liostunnel_app.app` -- a RELATIVE path, which
# says nothing about the root it is unpacked under. PackageInfo's
# install-location supplies that root. Built with `--install-location
# /tmp/wrong` the payload is byte-identical and the app installs to
# /tmp/wrong/Applications/liostunnel_app.app; the postinstall's fixed path
# then does not exist, `exec` fails, and the install dies AFTER the app has
# landed in the wrong place -- the same failure relocation causes, approached
# from the other end. Reading the relative path alone passed that package
# 13 out of 13.
[ -d "$app" ] && ok "the payload carries Applications/liostunnel_app.app" \
              || bad "no Applications/liostunnel_app.app in the payload"
loc="$(sed -n 's/.*install-location="\([^"]*\)".*/\1/p' "$pkginfo" | head -1)"
# pkgbuild omits the attribute entirely when --install-location is not passed,
# and an absent one means "/" -- so absent is correct, and anything else is not.
if [ -z "$loc" ] || [ "$loc" = "/" ]; then
  ok "the package installs relative to / -- the app lands in /Applications"
else
  bad "install-location is \"$loc\"; the app would land in $loc/Applications"
fi
[ -x "$app/Contents/MacOS/liostunnel_app" ] \
  && ok "the app executable is present and executable" \
  || bad "no executable at Contents/MacOS/liostunnel_app"

for f in liostunnel-helper install-helper.sh uninstall-helper.sh; do
  [ -x "$helper/$f" ] && ok "$f is inside the app and executable" \
                      || bad "missing or not executable: $f"
done
# Present is not usable, and `-f` cannot tell the difference. It passes on a
# zero-byte file and on one whose @UID@ placeholder has already been
# substituted or deleted -- and that placeholder is the only thing making this
# file a template. install-helper.sh does `sed "s/@UID@/$uid/" … > "$unit"`:
# with nothing left to substitute, the daemon installs with whatever uid was
# baked in (someone else's) or with the literal string (which the helper's u32
# parse rejects on startup). Either way it surfaces as a daemon that serves
# nobody and that launchd's KeepAlive keeps resurrecting.
if [ ! -f "$helper/liostunnel-helper.plist" ]; then
  bad "missing liostunnel-helper.plist"
elif ! grep -q '@UID@' "$helper/liostunnel-helper.plist"; then
  bad "liostunnel-helper.plist has no @UID@ for install-helper.sh to substitute"
else
  ok "the launchd plist is present, with its @UID@ placeholder intact"
fi
# A systemd unit in a macOS package reads as an oversight, not symmetry.
# Payload-wide, not one directory: a .service file anywhere in the payload
# installs exactly as far as one in Contents/Resources/helper, and a check
# scoped to that directory does not see it. Searching $tmp/p also retires the
# "does $helper exist" guard this needed before -- `find` over the whole
# payload cannot go vacuous when a subdirectory is missing, the way
# `[ ! -f "$helper/x" ]` does. verify-appimage.sh's mirror of this check was
# equally narrow and is now equally wide; the mirror argument cuts both ways.
strays="$(find "$tmp/p" -name '*.service' 2>/dev/null | tr '\n' ' ')"
if [ -z "$strays" ]; then
  ok "no systemd unit anywhere in the payload"
else
  bad "a systemd unit is in a macOS package: $strays"
fi

# A binary that runs on THIS platform -- not a placeholder, not the wrong arch.
v="$("$helper/liostunnel-helper" --version 2>&1)"
if [ $? -eq 0 ] && [ "${v#liostunnel-helper }" != "$v" ]; then
  ok "the bundled helper runs: $v"
else
  bad "the bundled helper did not run: $v"
fi

# Relocation. `pkgbuild --root` marks an app bundle relocatable by default,
# and Installer.app then redirects the payload onto any existing copy of that
# bundle id -- so the app lands somewhere else and the postinstall's fixed
# /Applications path does not exist. The top-level relocatable="false"
# attribute is a different thing and does not cover this.
# An empty `<relocate/>` is the correct state; `<relocate><bundle .../></relocate>`
# is the defect. Assert on the element's emptiness specifically -- `<bundle `
# alone appears throughout PackageInfo's own inventory (`<bundle-version>`,
# `<upgrade-bundle>`, `<strict-identifier>`), so grepping for it fails a
# perfectly good package. That mistake was made here first.
#
# But an empty `<relocate/>` only means something if there is a bundle to
# relocate. Delete Contents/Info.plist from the payload and pkgbuild registers
# no bundle components at all: `<relocate/>` is empty for want of anything to
# list, and the suite scored 13 of 13 on an app that cannot launch. So pair
# them -- the app must BE a registered bundle, and that bundle must not be
# relocatable. Anchored on the app's own path, which appears once, and not on
# the nested framework bundles that share its prefix.
if grep -q '<bundle path="\./Applications/liostunnel_app\.app"' "$pkginfo"; then
  ok "the app is a registered bundle component"
else
  bad "no bundle component for ./Applications/liostunnel_app.app -- is Contents/Info.plist missing?"
fi
if grep -q '<relocate/>' "$pkginfo"; then
  ok "the payload is not relocatable"
else
  bad "the payload is relocatable; it would install over a stray copy elsewhere"
fi

# The postinstall: present, executable, and behaving.
post="$(find "$tmp/x" -name postinstall | head -1)"
[ -n "$post" ] && [ -x "$post" ] && ok "postinstall is present and executable" \
                                 || bad "no executable postinstall"

# These used to be three greps -- for `--uid`, for `/dev/console`, and for
# `-ge 500|-lt 500`. A grep passes on the rule INVERTED, on the rule as dead
# code after the `exec`, and on the rule sitting in a comment. All three were
# built as real packages and all three scored a clean sweep, including the one
# that refuses every human and authorizes _mbsetupuser. So run the file.
#
# It can be run for real without touching anything and without root. Installer
# hands the destination volume's mountpoint to the script as $3, so pointing
# $3 at a temp tree makes the postinstall resolve its own helper path inside
# that tree -- where a stub install-helper.sh records the argv it was given and
# installs nothing. A fake `stat` earlier on PATH supplies the console uid and
# records how it was asked for it. Nothing is installed, nothing needs root,
# and /Library/LaunchDaemons is never reachable from here.
vol="$tmp/vol"
post_rc=0; post_argv=""; post_msg=""; stat_argv=""
run_post() { # $1: what `stat -f %u /dev/console` should print
  # ${tmp:?} and not $tmp: an `rm -rf` whose first component could go empty is
  # how this repo lost work once already.
  rm -rf "${vol:?}" "${tmp:?}/bin" "${tmp:?}/argv" "${tmp:?}/statargv"
  mkdir -p "$vol/Applications/liostunnel_app.app/Contents/Resources/helper" "$tmp/bin"
  stub="$vol/Applications/liostunnel_app.app/Contents/Resources/helper/install-helper.sh"
  { echo '#!/usr/bin/env bash'
    echo "printf '%s' \"\$*\" > '$tmp/argv'"; } > "$stub"
  { echo '#!/usr/bin/env bash'
    echo "printf '%s' \"\$*\" > '$tmp/statargv'"
    echo "printf '%s' '$1'"; } > "$tmp/bin/stat"
  chmod 755 "$stub" "$tmp/bin/stat"
  post_msg="$(PATH="$tmp/bin:$PATH" "$post" /dev/null "$vol" "$vol" 2>&1)"; post_rc=$?
  post_argv="$( [ -f "$tmp/argv" ] && cat "$tmp/argv" || echo '<not called>' )"
  stat_argv="$(cat "$tmp/statargv" 2>/dev/null || true)"
}

if [ -n "$post" ]; then
  # A real console user. This is also the target-volume assertion: the stub it
  # has to reach lives under $3, not under /Applications, so a postinstall with
  # the path hardcoded reaches nothing and reports <not called>.
  run_post 501
  [ "$post_argv" = "--uid 501" ] \
    && ok "postinstall hands install-helper.sh --uid 501, on the volume it was given" \
    || bad "postinstall did not authorize the console user on \$3 (got: $post_argv)"
  [ "$stat_argv" = "-f %u /dev/console" ] \
    && ok "postinstall reads the console user with stat -f %u /dev/console" \
    || bad "postinstall did not read /dev/console (stat argv: $stat_argv)"

  # "Not called, and exited non-zero" is NOT enough to call something a
  # refusal, and assuming it was cost this file a round: a postinstall with
  # /Applications hardcoded reaches no install-helper.sh at all, so `exec`
  # fails and it exits non-zero for EVERY uid -- and three mutants, including
  # one that refuses every human and authorizes _mbsetupuser, sailed through
  # the uid assertions on the strength of a crash. A refusal is a rule firing,
  # and the way to tell one from a crash is that a rule says something useful:
  # the refusal has to name the command that finishes the job, on the volume
  # the app actually went to. That is also the whole point of the message --
  # it lands in /var/log/install.log, where nobody looks, and it is the only
  # thing an admin gets.
  refused() { # $1: what it was asked to refuse
    if [ "$post_argv" != "<not called>" ]; then
      bad "postinstall authorized $1 (install-helper.sh got: $post_argv)"
    elif [ "$post_rc" -eq 0 ]; then
      bad "postinstall exited 0 on $1 without installing the helper"
    else
      case "$post_msg" in
        # A shell diagnostic where the refusal should be. `[ "$uid" -ge 500 ]`
        # on something that is not a number prints this and returns 2 -- the
        # `||` catches it, so the refusal is fail-CLOSED either way, and that
        # is precisely why deleting the `case` guard that parses the uid first
        # left this whole block green. The difference the guard makes is the
        # only thing anyone ever sees: whether install.log leads with
        # "integer expected" or with the sentence that says what to do.
        *"integer expected"*|*"integer expression expected"*)
          bad "postinstall refused $1 by way of a shell error, not a rule: $post_msg" ;;
        *"$vol/Applications/liostunnel_app.app/Contents/Resources/helper/install-helper.sh --uid"*)
          ok "postinstall refuses $1, and says how to finish the job by hand" ;;
        *)
          bad "postinstall failed on $1 without naming the command to run: $post_msg" ;;
      esac
    fi
  }

  # uid 0. install-helper.sh refuses this too, but a postinstall that gets
  # there has already decided root is a legitimate client.
  run_post 0
  refused "console uid 0"

  # PKG-3. _mbsetupuser during Setup Assistant is not 0, so install-helper.sh's
  # uid-0 guard does not catch it, and a helper serving an account that stops
  # existing the moment setup finishes is the failure this rule exists for.
  run_post 248
  refused "_mbsetupuser (uid 248)"

  # And an unreadable one -- the login window, or SSH with no console session.
  # `[ "$uid" -lt 500 ]` as an `if` condition is exempt from `set -e` and
  # returns 2 on a non-integer, which `if` reads as false: this used to fall
  # through to `exec install-helper.sh --uid ''`.
  run_post ""
  refused "a console uid it could not read"

  # Belt and braces on the volume: a literal leading /Applications anywhere in
  # the code is the hardcoded path coming back. Comments are stripped first --
  # this file's comments discuss /Applications at length.
  if sed 's/#.*//' "$post" | grep -qE "(^|[[:space:]\"'=])/Applications"; then
    bad "postinstall hardcodes /Applications instead of deriving it from \$3"
  else
    ok "postinstall does not hardcode /Applications"
  fi
fi

echo
echo "=== $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
