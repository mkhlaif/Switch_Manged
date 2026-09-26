# Network Device Tool — how to restart a device

You use this tool when a device (for example a PC, a phone or a printer) has stopped working on
the network and IT support asked you to restart its connection.

You need: your username and password, and the device's **MAC address** (a code like
`00:11:22:33:44:55`, usually printed on a label on the device).

## 1. Sign in

Open the address IT gave you in your browser. Enter your **username** and **password** and press
**Sign in**.

## 2. Enter the MAC address

Type the MAC address into the big box. You can type it with colons (`00:11:22:33:44:55`), dashes
(`00-11-22-33-44-55`) or without separators (`001122334455`).

## 3. Search

Press **SEARCH** and wait a few seconds.

## 4. Check the result

| You see | What it means | What to do |
|---|---|---|
| **Device Found** and a **Location** (for example *Building A - Floor 2 - Office 204*) | The device was found there | Continue with step 5 |
| **Device Not Found** | The device is not connected right now, or the code is wrong | Check the MAC address and try again |
| **Multiple locations detected** | The tool cannot be sure where the device is | Contact IT support |
| **This device cannot be restarted automatically** | For safety, this device must be handled by IT | Contact IT support |
| **Something went wrong** | A temporary problem | Try again later or contact IT support |

If the location reads *Location not recorded*, IT has not entered it yet — you can still restart
the device.

## 5. Restart the device

Press **RESTART DEVICE**. A window asks **"Restart Device?"** — the device will be disconnected
for a short moment. Press **Restart** to continue, or **Cancel** to stop.

You do **not** need to ask anyone for approval. Before anything happens, the system checks
automatically — directly on the network equipment — that it is really this device, that nothing
has changed since your search, and that restarting cannot affect other devices. If any check
fails, nothing is restarted and you see *"This device cannot be restarted automatically. Please
contact IT support."*

## 6. Wait for the confirmation

| Message | Meaning |
|---|---|
| **Device restarted successfully.** | Done. The device is back on the network. |
| **The device could not be verified after restart. Please contact IT support.** | The restart was done, but the system could not confirm that the device came back correctly. If it still does not work after a few minutes, contact IT support. The restart is **not** repeated automatically. |
| **The device could not be restarted. Please contact IT support.** | Nothing more to try — contact IT support. |
| **Please wait a minute before trying again.** | The same device was restarted a moment ago (by you or a colleague). Wait before trying again. |

Press **Search another device** for the next one. Sign out with the button at the top right when
you are done.

Good to know: every search and restart is recorded with your name. You cannot break anything by
searching; restarting only works for single devices that the system has safely identified, and
only while IT has opened a maintenance window.

---

### For IT administrators (not shown to MAC operators)

What the MAC_OPERATOR role can and cannot do, and every automatic check, is described in
[SECURITY.md § MAC_OPERATOR](SECURITY.md#4-mac_operator-direct-endpoint-restart) and
[ADMIN_GUIDE.md](ADMIN_GUIDE.md#mac-operators). In short, a restart is only possible when the
switch is declared as an **access** switch, the port is a High-confidence ACCESS port with a
single untagged VLAN and at most 3 MACs, the operation mode is **MAINTENANCE**, execution is
enabled and the restart strategy is lab-verified for that model and AOS version. The location
text comes from *Switches → Edit → Device locations per port* (or the switch's site/location).
