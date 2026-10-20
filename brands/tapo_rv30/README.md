# Brand assets

Icons for the Home Assistant integrations page. Home Assistant loads these from
the [home-assistant/brands](https://github.com/home-assistant/brands) repository,
not from this one, so they need a one-off pull request there:

1. Fork `home-assistant/brands`.
2. Copy `icon.png` and `icon@2x.png` (and optionally `logo.png`, `logo@2x.png`)
   into `custom_integrations/tapo_rv30/`.
3. Open the PR. The checks verify the sizes (256 and 512 px, square, PNG with
   transparency).

Once merged, the icon appears in HA within a day and the HACS `brands` check
passes, which is the last requirement for the HACS default store.

The artwork is original (a top-down robot vacuum), not TP-Link's trademark.
