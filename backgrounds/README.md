# Desktop backgrounds

Every image in this directory is installed to `/usr/share/backgrounds/ik-os/`
and registered in `/usr/share/gnome-background-properties/ik-os.xml`, so the
whole set appears in **Settings → Appearance → Background**.

The one a new account starts with is named in `build_files/build.sh`:

    DEFAULT_BG="ik-hubble.jpg"

It is a *default*, not a locked setting — users may pick any of the others, or
their own image. The build fails if the named file is not present, so renaming a
background cannot silently fall back to Bluefin's wallpaper.

## Adding or replacing

Drop the file in (`.jpg`, `.jpeg` or `.png`), and if it should become the new
default, update `DEFAULT_BG`. Display names are derived from the filename:
`ik-winter-forest.jpg` becomes "Winter Forest". Keep the `ik-` prefix.

Target 2560x1440 or larger; the current set is all 2560x1440 and adds about
37 MB to the image.

## How the default is applied

Through a gschema override (`zz2-ik-os-modifications.gschema.override`), which
is the same mechanism Bluefin uses for its own default (`zz0-bluefin-*`). The
`zz2-` prefix sorts after Bluefin's files and later overrides win. Using a
gschema override instead of a dconf database keeps this entirely inside `/usr`,
so there is no `/etc` three-way merge on upgrades.