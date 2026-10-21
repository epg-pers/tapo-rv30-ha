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
- Checks that CI runs: `ruff check custom_components tests`, `pyflakes custom_components tests` and `pytest -q tests`
- The card is plain JavaScript in `custom_components/tapo_rv30/frontend/`, no build step;
  `node --check` on it is enough for syntax.
- Keep `strings.json` and `translations/en.json` identical (Home Assistant reads the
  latter at runtime).
- Add a line to `CHANGELOG.md` under the version you are changing.

## Testing against a real robot: beta releases

Set `version` in `manifest.json` to a beta, e.g. `0.18.0b1`, add a `## v0.18.0b1` section
to `CHANGELOG.md`, and push the branch. CI publishes it as a pre-release. In HACS, open the
integration, enable "Show beta versions", pick `v0.18.0b1`, download and restart Home
Assistant. Iterate with `b2`, `b3`. When it is good, merge to `main` with the plain
version (`0.18.0`) and the stable release is cut from there. No test branches, no manual
branch clean-up; delete the merged branch and the betas stay as history.

Two rules learned the hard way, see `docs/protocol.md`:

1. Never send unknown, setup, inherit, commissioning or map backup / recovery methods to a
   robot while it is cleaning, returning or paused. A batch of such reads during a run
   coincided with an RV30 losing its saved maps, clean history and cloud backups.
2. Say in the pull request what you tested on hardware and on which model and firmware.
   Untested code paths are fine to contribute, labelled as such.

## Releases

Releases are cut by CI: bumping `version` in `manifest.json` on `main` (with the matching
notes at the top of `CHANGELOG.md`) creates the GitHub release; a beta version on any
branch creates a pre-release. Day-to-day work goes on a branch, gets a beta, and is merged
to `main` once CI is green and the hardware checks pass.

## Docs

The `docs/` folder is published as a site by GitHub Pages (Jekyll, no build step): any
Markdown file added there appears on the site, and links between `.md` files turn into
page links. `docs/index.md` is the landing page; add new pages to its list.
