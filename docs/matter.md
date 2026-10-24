# Matter

The RV30 Max Plus reports a `matter` component and the app has a "Bind to Matter" page.
What the integration exposes (calls and fields taken from the app's code, read-only parts
verified on an RV30 Max Plus, firmware 1.3.3):

- **Matter sensor** (diagnostic, disabled by default): `Not paired`, `Pairing window open`
  or `Paired`, with attributes `fabrics` (label, vendor id, fabric index of every
  ecosystem the robot is paired to) and `window_seconds_left`.
- `tapo_rv30.get_matter_setup_code` (admin only): returns the 11-digit manual pairing code
  (`setup_code`) and the QR payload (`setup_payload`). Run it from Developer tools >
  Actions with "Return response". The code is deliberately not an entity: entity states and
  attributes can be read by every user and are kept in the recorder's history.
- **Open Matter Pairing Window** button (diagnostic): the app's `startCommission`. The
  robot then accepts a new pairing for a few minutes (`expired_time` counts down); the
  sensor shows the window and the time left, projected from the last read so it does not
  poll the robot for it.
- `tapo_rv30.remove_matter_fabric`: the app's `removeBindFabric`.

**About the code changing.** The setup code and QR payload are the robot's fixed ones
(`getMatterSetupInfo` returned the same values every time it was read over several hours;
they are what is printed on the robot). What is time-limited is the pairing *window*: the
app opens one when you view the page and shows a countdown, and the robot only accepts a
new ecosystem while it is open. So the flow is: enable the Matter sensor, press the button,
then add the robot in Home Assistant's Matter integration (or any other ecosystem) with
the code from `get_matter_setup_code` before the window closes (the code is also printed on
the robot).

Before 0.32 the code was a Matter Setup Code sensor and an attribute of the Matter sensor.
0.32 removes both; if you had them enabled, older values may still be in the recorder's
history, which `recorder.purge_entities` on those two sensors clears. The Matter sensor is off
by default; enable it when you need it. The status and setup-info
reads and the pairing-window button are verified on an RV30 Max Plus (a 15-minute window,
the code unchanged); the remove service follows the app's code and is untested, the test
robot not being paired to anything.
