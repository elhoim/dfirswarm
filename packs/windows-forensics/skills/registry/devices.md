---
id: registry/devices
title: USB and removable devices
when: Data may have left on a stick, or a device is part of the story.
needs: [registry/system-profile]
tools: [regkv]
requires_host: [icat]
---

Four keys, read together, give a device, when it was first and last seen, who
mounted it and what letter it had.

    SYSTEM\ControlSet00n\Enum\USBSTOR            vendor, product, serial per device
    SYSTEM\ControlSet00n\Enum\USB                the same devices by VID and PID
    SYSTEM\MountedDevices                        drive letter to device mapping
    SOFTWARE\Microsoft\Windows Portable Devices\Devices   friendly name and letter
    NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        which user mounted it

The serial number under `USBSTOR` is the device's own; a second character of `&`
means the device did not supply one and Windows made it up, which weakens any
claim that two sightings are the same stick.

First and last connection times come from the device subkey's `Properties`
under the standard property GUIDs. Quote the key path with the value.

Pair a device with what moved: link files pointing at its letter, jump list
entries, the shell bags for its folders. A device alone proves attachment, not
exfiltration.
