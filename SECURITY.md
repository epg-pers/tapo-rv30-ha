# Security policy

## Supported versions

Only the latest release gets fixes. Update through HACS.

## What this integration touches

It talks to the robot on your local network only, authenticating with your Tapo account
credentials over the robot's own TPAP or AES transport. The credentials are stored in Home
Assistant's config entry; the session cache in `.storage/tapo_rv30/` is written with mode
0600 and holds session keys, not the password. Diagnostics downloads redact credentials.
The Matter sensors are off by default because the setup code plus an open pairing window
is all someone on your network needs to pair the robot elsewhere.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting on this repository (Security tab, Report a vulnerability). You
will get a reply within a week. If the report concerns the robot's firmware or TP-Link's
cloud rather than this integration, report it to TP-Link as well:
https://www.tp-link.com/en/support/contact-technical-support/
