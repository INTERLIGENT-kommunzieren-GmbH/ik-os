# Teams video backgrounds

Every image here is installed to `/usr/share/ik-os/teams-backgrounds/` as a
1920x1080 background plus a 280x158 thumbnail, and offered to Microsoft Teams
through `teams-for-linux`.

## How they reach the picker

Teams builds the background picker itself and gives no API for adding to it.
What `teams-for-linux` can do is redirect every request Teams makes for
`statics.teams.cdn.office.net/evergreen-assets/backgroundimages/…` to a local
service. A company background therefore appears by being served **in place of
one of Microsoft's own assets** — the names listed in `slots.txt`, matched to
the images in sorted order.

Everything not listed in `slots.txt` is proxied straight back to Microsoft by
`ik-teams-backgrounds.service`, so the rest of the picker looks untouched. Turn
the proxy off and you get a grid of empty tiles instead — the redirect catches
*all* of Microsoft's assets, whether we have a replacement or not.

Note the consequence: the tiles carry Microsoft's names internally. The picker
shows no captions, so this is invisible in use, but a background you set is
recorded by Teams as e.g. `teamsBackgroundHome`.

## Adding or replacing

Drop the file in (`.jpg`, `.jpeg` or `.png`) and add a spare name to `slots.txt`
if all of them are taken — the build fails when there are fewer slots than
images. Keep the `ik-` prefix.

Source images should be 1920x1080 or larger. The current set is 1680x1120 (3:2),
which the build centre-crops to 16:9; re-exporting at 16:9 avoids losing the top
and bottom of the frame.

## If an image stops appearing

Microsoft retired the asset name it was mapped to. `journalctl -u
ik-teams-backgrounds` logs every asset Teams asks for, marked `ik` (served from
here) or `ms` (proxied) — pick a name from that log and replace the dead line in
`slots.txt`.
