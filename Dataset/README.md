# CIoT Device Testbed

The following table presents the CIoT devices utilized as a testbed in the study:

| ID | Device Model          | Brand     | Actions                          |
|-----|----------------------|-----------|----------------------------------|
|  0  | PAN Coordinator      | EFR32MG21 |//                                |
|2 (a)| Hue Motion Sensor    | Philips   | Motion, Light Intensity          |
|7 (b)| TS011F               | Tuya      | On & Off, Power Consumption      |
|6 (c)| Plug Z3              | Ledvance  | On & Off, Power Consumption      |
|3 (d)| Hue White Lamp       | Philips   | On & Off, Luminosity             |
|4 (e)| Door Window Sensor   | Aqara     | Open & Closed                    |
|1 (f)| ZBSA-Motion Sensor   | Woolley   | Motion                           |
|5 (g)| TS0043 Switch        | Tuya      | Short press, Long press, Double press |
|8    | Unlabeled Traffic    | //        | //                               |


```bash

Network Settings
PAN ID: EDAA
Extended PAN ID: 85:14:97:ea:9c:31:4b:6c
Channel: 15
Coordinator IEEE: 00:12:4b:00:24:c2:9c:2b
Network key: 82:67:c2:d9:37:29:08:14:c2:de:a6:94:40:79:e5:5c
Radio type: znp

Zigbee Coordinator
Zigbee Home Automation
Device info
ZNP = Texas Instruments Z-Stack ZNP protocol: CC253x, CC26x2, CC13x2
by ZHA
Zigbee info
IEEE: 00:12:4b:00:24:c2:9c:2b
Nwk: 0x0000
Device Type: Coordinator
LQI: Unknown
RSSI: Unknown
Last Seen: 2023-07-06T19:37:55
Power Source: Mains

(a)
100%
Zigbee Home Automation
Device info
SML001
by Philips
Connected via Zigbee Coordinator
Firmware: 0x42006bb7
Zigbee info
IEEE: 00:17:88:01:08:68:18:1e
Nwk: 0xe40d
Device Type: EndDevice
LQI: 138
RSSI: Unknown
Last Seen: 2023-07-06T19:41:41
Power Source: Battery or Unknown
Quirk: zhaquirks.philips.motion.PhilipsMotion

(b)
Zigbee Home Automation
Device info
TS011F
by _TZ3000_typdpbpg
Connected via Zigbee Coordinator
Zigbee info
IEEE: a4:c1:38:36:0e:35:e3:d8
Nwk: 0x6ee1
Device Type: Router
LQI: 156
RSSI: Unknown
Last Seen: 2023-07-06T19:41:05
Power Source: Mains
Quirk: zhaquirks.tuya.ts011f_plug.Plug

(c)
Zigbee Home Automation
Device info
Plug Z3
by LEDVANCE
Connected via Zigbee Coordinator
Zigbee info
IEEE: f0:d1:b8:00:00:14:f9:11
Nwk: 0xb843
Device Type: Router
LQI: 57
RSSI: Unknown
Last Seen: 2023-07-06T19:26:58
Power Source: Mains

(d)
Zigbee Home Automation
Device info
LWA001
by Signify Netherlands B.V.
Connected via Zigbee Coordinator
Firmware: 0x01002400
Zigbee info
IEEE: 00:17:88:01:06:e3:0a:cb
Nwk: 0xba20
Device Type: Router
LQI: 126
RSSI: Unknown
Last Seen: 2023-07-06T19:39:20
Power Source: Mains

(e)
80%
Zigbee Home Automation
Device info
lumi.sensor_magnet.aq2
by LUMI
Connected via Zigbee Coordinator
Zigbee info
IEEE: 00:15:8d:00:08:c9:c7:5a
Nwk: 0xc221
Device Type: EndDevice
LQI: 117
RSSI: Unknown
Last Seen: 2023-07-06T19:27:10
Power Source: Battery or Unknown
Quirk: zhaquirks.xiaomi.aqara.magnet_aq2.MagnetAQ2

(f)
100%
Zigbee Home Automation
Device info
MS01
by eWeLink
Connected via Zigbee Coordinator
Zigbee info
IEEE: 00:12:4b:00:29:28:02:6b
Nwk: 0x5d11
Device Type: EndDevice
LQI: 144
RSSI: Unknown
Last Seen: 2023-07-06T19:40:09
Power Source: Battery or Unknown

(g)
100%
Zigbee Home Automation
Device info
TS0043
by _TZ3000_gbm10jnj
Connected via Zigbee Coordinator
Zigbee info
IEEE: 94:34:69:ff:fe:b7:c1:f3
Nwk: 0x3094
Device Type: EndDevice
LQI: 150
RSSI: Unknown
Last Seen: 2023-07-06T19:39:20
Power Source: Battery or Unknown
Quirk: zhaquirks.tuya.ts0043.TuyaSmartRemote0043TO

```
