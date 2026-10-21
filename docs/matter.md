# Matter

The RV30 Max Plus reports a `matter` component and the app has a "Bind to Matter" page.
What the integration exposes (calls and fields taken from the app's code, read-only parts
verified on an RV30 Max Plus, firmware 1.3.3):

- **Matter sensor** (diagnostic, disabled by default): `Not paired`, `Pairing window open`
  or `Paired`, with attributes `fabrics` (label, vendor id, fabric index of every
  ecosystem the robot is paired to) and `window_seconds_left`.
- **Matter Setup Code sensor** (diagnostic, disabled by default): the 11-digit manual
  pairing code as its state, so it reads straight off the device page; the QR payload is
  its `setup_payload` attribute.
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
the code from the Matter Setup Code sensor before the window closes.

Both sensors are off by default because the setup code lets anyone on your network pair
the robot while a window is open. Enable them when you need them. The status and setup-info
reads and the pairing-window button are verified on an RV30 Max Plus (a 15-minute window,
the code unchanged); the remove service follows the app's code and is untested, the test
robot not being paired to anything.
