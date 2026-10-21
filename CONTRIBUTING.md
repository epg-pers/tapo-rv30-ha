# Contributing

Thanks for helping. This is a small project; a clear issue is as welcome as a pull request.

## Reporting a bug

Open a bug report with the template. It asks for the things every robot bug needs:
model, firmware, Home Assistant version, integration version, the diagnostics download
(Settings, Devices and services, Tapo Robot Vacuum, the three-dot menu, Download
diagnostics; credentials are redacted) and the relevant lines from Settings, System, Logs.

If a method on your robot answers differently from what `docs/protocol.md` says,
include the raw response from `tapo_rv30.send_raw` with "Return response" ticked in
Developer Tools. That is how most model differences get found.

## Working on the code

- Python 3.13 and the test requirements: `pip install -r tests/requirements.txt`
- Checks that CI runs: `pyflakes custom_components tests` and `pytest -q tests`
- The card is plain JavaScript in `custom_components/tapo_rv30/frontend/`, no build step;
  `node --check` on it is enough for syntax.
- Keep `strings.json` and `translations/en.json` identical (Home Assistant reads the
  latter at runtime).
- Add a line to `CHANGELOG.md` under the version you are changing.

## Testing against a real robot

Push your branch and point HACS at it: in HACS open the integration, choose Redownload,
pick the branch name as the version, then restart Home Assistant. The map, services and
entities can then be checked against hardware.

Two rules learned the hard way, see `docs/protocol.md`:

1. Never send unknown, setup, inherit, commissioning or map backup / recovery methods to a
   robot while it is cleaning, returning or paused. A batch of such reads during a run
   coincided with an RV30 losing its saved maps, clean history and cloud backups.
2. Say in the pull request what you tested on hardware and on which model and firmware.
   Untested code paths are fine to contribute, labelled as such.

## Releases

Releases are cut by CI: bumping `version` in `manifest.json` on `main` (with the matching
notes at the top of `CHANGELOG.md`) creates the GitHub release. Day-to-day work goes on a
branch and is merged to `main` once CI is green and the hardware checks pass.
