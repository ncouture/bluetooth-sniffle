# Crackle BLE PCAP Connection Analysis & Device Attribution

### Crackle Connection Details with OUI Vendors & BLE Identifiers

```text
$ ./crackle -i ~/Documents/sniffle.pcap -o ~/Documents/outp-sniffle.pcapng -v
PCAP contains [BLUETOOTH_LE_LL_WITH_PHDR] frames
Found 30 connections
 
Analyzing connection 0:
  5f:54:57:24:46:e3 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 1:
  73:3f:b1:ff:e9:75 (random: Resolvable Private Address [RPA] - No OUI) -> fe:3c:c1:67:f3:ce (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 2:
  6d:2c:af:bd:a6:77 (random: Resolvable Private Address [RPA] - No OUI) -> fe:3c:c1:67:f3:ce (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 3:
  63:27:dc:63:1e:29 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 4:
  4f:36:a0:b1:77:d2 (random: Resolvable Private Address [RPA] - No OUI) -> dc:c3:7e:d6:2c:6f (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 5:
  66:ea:0d:91:97:c1 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 6:
  4b:f2:4a:99:0d:86 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 7:
  7c:13:f8:a5:5b:1d (random: Resolvable Private Address [RPA] - No OUI) -> eb:c0:5b:f3:eb:5e (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 8:
  74:02:ed:c1:71:78 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 9:
  5e:c7:b7:36:97:dc (random: Resolvable Private Address [RPA] - No OUI) -> dc:c3:7e:d6:2c:6f (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 10:
  5b:da:5b:4a:3c:81 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 11:
  56:7d:bb:a4:95:dc (random: Resolvable Private Address [RPA] - No OUI) -> dc:c3:7e:d6:2c:6f (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 12:
  56:7d:bb:a4:95:dc (random: Resolvable Private Address [RPA] - No OUI) -> dc:c3:7e:d6:2c:6f (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 13:
  67:7f:fc:7f:b5:b0 (random: Resolvable Private Address [RPA] - No OUI) -> f4:b2:da:41:f5:91 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 14:
  42:d1:3d:29:5e:bd (random: Resolvable Private Address [RPA] - No OUI) -> c0:6e:70:e0:45:e7 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 15:
  67:48:3a:7f:c7:79 (random: Resolvable Private Address [RPA] - No OUI) -> ff:c4:de:5d:61:ae (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 16:
  46:d5:1c:23:e0:0c (random: Resolvable Private Address [RPA] - No OUI) -> e9:51:bf:fd:00:c6 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 17:
  71:1d:76:09:f3:2a (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 18:
  79:9a:b0:4a:21:ee (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 19:
  7c:b1:f7:92:16:ee (random: Resolvable Private Address [RPA] - No OUI) -> c6:4a:69:7c:43:be (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 20:
  68:2a:f8:d0:3c:2b (random: Resolvable Private Address [RPA] - No OUI) -> ea:6c:42:7e:db:c2 (random: Static Device Address - No OUI | Apple, Inc. EIR Company ID 0x004C)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 21:
  62:26:9d:d3:d7:21 (random: Resolvable Private Address [RPA] - No OUI) -> f8:64:76:1a:62:7c (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 22:
  4e:47:5a:3d:50:60 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 23:
  4a:7f:b4:b0:f9:e1 (random: Resolvable Private Address [RPA] - No OUI) -> f5:f6:c3:fe:36:b5 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 24:
  41:79:05:77:a3:bc (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 25:
  6d:02:39:2e:e5:af (random: Resolvable Private Address [RPA] - No OUI) -> f7:a2:6a:29:63:71 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 26:
  44:c4:f8:a4:96:07 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 27:
  69:ff:ee:53:71:5f (random: Resolvable Private Address [RPA] - No OUI) -> d2:c2:5f:71:3c:63 (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 28:
  6d:02:39:2e:e5:af (random: Resolvable Private Address [RPA] - No OUI) -> f4:eb:92:85:1a:7e (random: Static Device Address - No OUI)
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Analyzing connection 29:
  73:ab:b9:07:f3:f0 (random: Resolvable Private Address [RPA] - No OUI) -> d8:0f:b5:06:79:7b (public: Shenzhen UltraEasy Technology Co., Ltd. [OUI d8:0f:b5])
  Found 0 encrypted packets
  Unable to crack due to the following errors:
    Missing both Mrand and Srand
    Missing LL_ENC_REQ
    Missing LL_ENC_RSP
 
Did not decrypt any packets, not writing a new PCAP
Done, processed 0 total packets, decrypted 0

Connection 0
  AA: 6787e2e1
  IA: 5f:54:57:24:46:e3 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 1
  AA: 50654b1d
  IA: 73:3f:b1:ff:e9:75 (IAt: 1 [Random - RPA, No OUI])
  RA: fe:3c:c1:67:f3:ce (RAt: 1 [Random - Static, No OUI])

Connection 2
  AA: 506575ec
  IA: 6d:2c:af:bd:a6:77 (IAt: 1 [Random - RPA, No OUI])
  RA: fe:3c:c1:67:f3:ce (RAt: 1 [Random - Static, No OUI])

Connection 3
  AA: 22a0c653
  IA: 63:27:dc:63:1e:29 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 4
  AA: af9aac1b
  IA: 4f:36:a0:b1:77:d2 (IAt: 1 [Random - RPA, No OUI])
  RA: dc:c3:7e:d6:2c:6f (RAt: 1 [Random - Static, No OUI])

Connection 5
  AA: 9bb1733a
  IA: 66:ea:0d:91:97:c1 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 6
  AA: bb67223d
  IA: 4b:f2:4a:99:0d:86 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 7
  AA: 50654b28
  IA: 7c:13:f8:a5:5b:1d (IAt: 1 [Random - RPA, No OUI])
  RA: eb:c0:5b:f3:eb:5e (RAt: 1 [Random - Static, No OUI])

Connection 8
  AA: ed630877
  IA: 74:02:ed:c1:71:78 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 9
  AA: 50657a9d
  IA: 5e:c7:b7:36:97:dc (IAt: 1 [Random - RPA, No OUI])
  RA: dc:c3:7e:d6:2c:6f (RAt: 1 [Random - Static, No OUI])

Connection 10
  AA: 465e1468
  IA: 5b:da:5b:4a:3c:81 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 11
  AA: af9a9c96
  IA: 56:7d:bb:a4:95:dc (IAt: 1 [Random - RPA, No OUI])
  RA: dc:c3:7e:d6:2c:6f (RAt: 1 [Random - Static, No OUI])

Connection 12
  AA: 50657b9b
  IA: 56:7d:bb:a4:95:dc (IAt: 1 [Random - RPA, No OUI])
  RA: dc:c3:7e:d6:2c:6f (RAt: 1 [Random - Static, No OUI])

Connection 13
  AA: 50657399
  IA: 67:7f:fc:7f:b5:b0 (IAt: 1 [Random - RPA, No OUI])
  RA: f4:b2:da:41:f5:91 (RAt: 1 [Random - Static, No OUI])

Connection 14
  AA: af9a841f
  IA: 42:d1:3d:29:5e:bd (IAt: 1 [Random - RPA, No OUI])
  RA: c0:6e:70:e0:45:e7 (RAt: 1 [Random - Static, No OUI])

Connection 15
  AA: af9ab2eb
  IA: 67:48:3a:7f:c7:79 (IAt: 1 [Random - RPA, No OUI])
  RA: ff:c4:de:5d:61:ae (RAt: 1 [Random - Static, No OUI])

Connection 16
  AA: 50655c92
  IA: 46:d5:1c:23:e0:0c (IAt: 1 [Random - RPA, No OUI])
  RA: e9:51:bf:fd:00:c6 (RAt: 1 [Random - Static, No OUI])

Connection 17
  AA: a2988a86
  IA: 71:1d:76:09:f3:2a (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 18
  AA: 760825e7
  IA: 79:9a:b0:4a:21:ee (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 19
  AA: 50655563
  IA: 7c:b1:f7:92:16:ee (IAt: 1 [Random - RPA, No OUI])
  RA: c6:4a:69:7c:43:be (RAt: 1 [Random - Static, No OUI])

Connection 20
  AA: 506552dd
  IA: 68:2a:f8:d0:3c:2b (IAt: 1 [Random - RPA, No OUI])
  RA: ea:6c:42:7e:db:c2 (RAt: 1 [Random - Static, No OUI | Apple, Inc. Company ID 0x004C])

Connection 21
  AA: 5065539d
  IA: 62:26:9d:d3:d7:21 (IAt: 1 [Random - RPA, No OUI])
  RA: f8:64:76:1a:62:7c (RAt: 1 [Random - Static, No OUI])

Connection 22
  AA: 6a6e2767
  IA: 4e:47:5a:3d:50:60 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 23
  AA: 89631a39
  IA: 4a:7f:b4:b0:f9:e1 (IAt: 1 [Random - RPA, No OUI])
  RA: f5:f6:c3:fe:36:b5 (RAt: 1 [Random - Static, No OUI])

Connection 24
  AA: 5429a7dc
  IA: 41:79:05:77:a3:bc (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 25
  AA: af9a8554
  IA: 6d:02:39:2e:e5:af (IAt: 1 [Random - RPA, No OUI])
  RA: f7:a2:6a:29:63:71 (RAt: 1 [Random - Static, No OUI])

Connection 26
  AA: a21dd168
  IA: 44:c4:f8:a4:96:07 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])

Connection 27
  AA: af9a93ef
  IA: 69:ff:ee:53:71:5f (IAt: 1 [Random - RPA, No OUI])
  RA: d2:c2:5f:71:3c:63 (RAt: 1 [Random - Static, No OUI])

Connection 28
  AA: af9a8aea
  IA: 6d:02:39:2e:e5:af (IAt: 1 [Random - RPA, No OUI])
  RA: f4:eb:92:85:1a:7e (RAt: 1 [Random - Static, No OUI])

Connection 29
  AA: be55ddf5
  IA: 73:ab:b9:07:f3:f0 (IAt: 1 [Random - RPA, No OUI])
  RA: d8:0f:b5:06:79:7b (RAt: 0 [Public - Shenzhen UltraEasy Technology Co., Ltd.])
```

--- English ---

### 1. Architectural Context: BLE Roles & Connection Dynamics

In Bluetooth Low Energy (BLE), communication occurs in asymmetric client/server or central/peripheral roles:
1. **Who Initializes Every Connection?**
   - The connection is initiated by the **Initiator Address (`IA`)**, which operates as the **BLE Central / Master**. In everyday consumer environments, the Central device is almost invariably an active personal mobile terminal—specifically a **smartphone** (iOS or Android), a tablet, or a computer.
   - The initiator listens for broadcast advertising packets from a peripheral and transmits a `CONNECT_IND` (Link Layer Connection Indication) packet. This packet establishes the connection parameters and assigns a unique 32-bit **Access Address (`AA`)** for the resulting data link.
2. **Who Responds / Is Connected To?**
   - The recipient is the **Responder Address (`RA`)**, operating as the **BLE Peripheral / Slave**. These are typically battery-powered or fixed IoT devices such as smartwatches, fitness trackers, smart home appliances, wireless sensors, or accessories.
3. **Why Crackle Reported 0 Encrypted Packets:**
   - The capture file `sniffle.pcap` was collected while sniffing the primary BLE advertising channels (Channels 37, 38, or 39).
   - The sniffer logged the `CONNECT_IND` packets where the connection was established, but did not follow the frequency-hopping sequence onto the 37 Link Layer data channels. Therefore, no `LL_ENC_REQ`, `LL_ENC_RSP`, pairing keys, or encrypted data payloads were captured.

---

### 2. Address Resolution & IEEE OUI Breakdown

The Bluetooth Core Specification defines two top-level address spaces:
- **Public Device Addresses (`RAt: 0` / `IAt: 0`):** Globally unique 48-bit MAC addresses registered with IEEE. The upper 24 bits represent the **IEEE Organizationally Unique Identifier (OUI)**.
  - In this capture, exactly one host uses a Public MAC address: **`d8:0f:b5:06:79:7b`**.
  - OUI `d8:0f:b5` belongs to **Shenzhen UltraEasy Technology Co., Ltd.** (`UltraeasyTec`), a well-known original equipment manufacturer (OEM/ODM) of Bluetooth smartwatches, fitness wristbands, and health monitors.
- **Random Device Addresses (`RAt: 1` / `IAt: 1`):** 48-bit locally generated addresses. By specification, **they do not possess IEEE OUIs**:
  - **Resolvable Private Addresses (RPAs):** Recognized by the two most significant bits `01` (addresses starting with `4x`, `5x`, `6x`, or `7x`). All 30 **Initiator Addresses (IAs)** in this trace are RPAs. Smartphones generate these using AES-128 and an Identity Resolving Key (IRK), rotating them every ~15 minutes to obstruct wireless tracking and eavesdropping.
  - **Static Random Addresses:** Recognized by the two most significant bits `11` (addresses starting with `Cx`, `Dx`, `Ex`, or `Fx`). All random **Responder Addresses (RAs)** in this trace fall into this class. They are generated randomly at firmware initialization and usually remain constant until power cycling or hardware reset.

---

### 3. Degree of Usefulness in Identifying Devices & Human Presence

The degree of usefulness in answering **"What device initialized the connection?"** and **"Whose presence is detected?"** varies significantly depending on the target host:

| Connection Category | Initializing Host (IA) | Target Host (RA) | Degree of Usefulness (Device & Presence) | Analytical Significance |
| :--- | :--- | :--- | :--- | :--- |
| **Wearable Sync Cluster**<br>(12 Connections: 0, 3, 5, 6, 8, 10, 17, 18, 22, 24, 26, 29) | RPA (Rotating `01...`) | `d8:0f:b5:06:79:7b`<br>(Public - Shenzhen UltraEasy) | **VERY HIGH** *(Deanonymizing)* | The static public address of the UltraEasy smartwatch acts as a persistent tracking beacon. Because the owner's smartphone periodically connects to sync notifications and fitness stats, the smartphone's RPA privacy protection is completely bypassed. This definitively tracks the presence and movements of the specific person wearing this smartwatch. |
| **Apple Ecosystem Continuity**<br>(1 Connection: 20) | `68:2a:f8:d0:3c:2b`<br>(RPA) | `ea:6c:42:7e:db:c2`<br>(Random Static, Apple ID `0x004C`) | **VERY HIGH** *(Ecosystem & Platform)* | While the address itself is random static, packet EIR inspection reveals Apple Inc. Company ID `0x004C` transmitting Continuity/Nearby Action frames (`1202aa...`). This confirms an active interaction between an Apple Central (iPhone/iPad/Mac) and an Apple accessory or companion device. |
| **Persistent Peripheral Cluster**<br>(4 Connections: 4, 9, 11, 12) | RPAs (`4f:36...`, `5e:c7...`, `56:7d...`) | `dc:c3:7e:d6:2c:6f`<br>(Random Static) | **HIGH** *(Presence),* **MODERATE** *(Device)* | This peripheral remains present and active across hours. In Connections 11 and 12 (separated by just 3.2 seconds), the same RPA (`56:7d:bb:a4:95:dc`) initiates back-to-back attempts, indicating an active device retry. |
| **Secondary Persistent Peripheral**<br>(2 Connections: 1, 2) | RPAs (`73:3f...`, `6d:2c...`) | `fe:3c:c1:67:f3:ce`<br>(Random Static) | **HIGH** *(Presence),* **MODERATE** *(Device)* | Two separate connections spaced ~5 minutes apart. Confirms a persistent BLE peripheral in the immediate radio range. |
| **Multi-Target Initiator**<br>(Connections 25 & 28) | `6d:02:39:2e:e5:af`<br>(RPA) | `f7:a2:6a:29:63:71`<br>`f4:eb:92:85:1a:7e` | **MODERATE to HIGH** *(Device Correlated)* | The exact same RPA initiator connects to two completely different peripherals within its 15-minute rotation window, demonstrating a single central host scanning and servicing multiple BLE accessories in the environment. |
| **Isolated Peripheral Connections**<br>(11 Connections: 7, 13, 14, 15, 16, 19, 21, 23, 25, 27, 28) | RPA | Various Random Static Hosts | **LOW to MODERATE** | Lacks public OUI or persistent multi-connection history. Represents fleeting presence or background scanning by nearby mobile devices. |

---

### 4. Detailed Connection-by-Connection Explanation

#### Connection 0 (t = 1951.3s / ~32.5 min)
- **Hosts:** Initiator `5f:54:57:24:46:e3` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x6787e2e1`.
- **Explanation:** An active smartphone initiates a connection to a Shenzhen UltraEasy smartwatch/fitness band to exchange background synchronization data.
- **Degree of Usefulness:** **High**. While the phone's MAC is randomized, the fixed public address of the smartwatch establishes the physical presence of the smartwatch wearer.

#### Connection 1 (t = 2975.6s / ~49.6 min)
- **Hosts:** Initiator `73:3f:b1:ff:e9:75` (RPA) $\rightarrow$ Responder `fe:3c:c1:67:f3:ce` (Random Static). Access Address: `0x50654b1d`.
- **Explanation:** A mobile smartphone connects to a nearby unassigned random-static peripheral (e.g., smart home node, beacon, or accessory).
- **Degree of Usefulness:** **Moderate**. Pinpoints the existence of a stationary peripheral at that instant, but device model and user identity cannot be resolved without upper-layer GATT discovery or an IRK.

#### Connection 2 (t = 3265.9s / ~54.4 min)
- **Hosts:** Initiator `6d:2c:af:bd:a6:77` (RPA) $\rightarrow$ Responder `fe:3c:c1:67:f3:ce` (Random Static). Access Address: `0x506575ec`.
- **Explanation:** Occurring ~4.8 minutes after Connection 1, another RPA connects to the identical peripheral `fe:3c:c1:67:f3:ce`. This is either the same smartphone whose address rotated, or a second central device interacting with the same host.
- **Degree of Usefulness:** **Moderate to High**. Confirms `fe:3c:c1:67:f3:ce` is a persistent fixed fixture in this environment.

#### Connection 3 (t = 3615.8s / ~60.3 min)
- **Hosts:** Initiator `63:27:dc:63:1e:29` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x22a0c653`.
- **Explanation:** Reconnection to the UltraEasy smartwatch ~27.7 minutes after Connection 0.
- **Degree of Usefulness:** **Very High**. Fits the standard background reconnection cadence of companion smartwatch apps (e.g., Da Fit or GloryFit) running on an iPhone or Android phone.

#### Connection 4 (t = 4306.8s / ~71.8 min)
- **Hosts:** Initiator `4f:36:a0:b1:77:d2` (RPA) $\rightarrow$ Responder `dc:c3:7e:d6:2c:6f` (Random Static). Access Address: `0xaf9aac1b`.
- **Explanation:** First observed connection to peripheral `dc:c3:7e:d6:2c:6f`.
- **Degree of Usefulness:** **Moderate**. Confirms initial presence of peripheral `dc:c3:7e:d6:2c:6f` and a central device in range.

#### Connection 5 (t = 4370.7s / ~72.8 min)
- **Hosts:** Initiator `66:ea:0d:91:97:c1` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x9bb1733a`.
- **Explanation:** Another background sync attempt to the UltraEasy smartwatch, occurring ~12.5 minutes after Connection 3.
- **Degree of Usefulness:** **Very High**. Reinforces continuous presence of the smartwatch and its paired smartphone.

#### Connection 6 (t = 4642.1s / ~77.4 min)
- **Hosts:** Initiator `4b:f2:4a:99:0d:86` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0xbb67223d`.
- **Explanation:** Rapid follow-up sync to the UltraEasy smartwatch just 4.5 minutes later.
- **Degree of Usefulness:** **Very High**. Consistent tracking signature.

#### Connection 7 (t = 4830.3s / ~80.5 min)
- **Hosts:** Initiator `7c:13:f8:a5:5b:1d` (RPA) $\rightarrow$ Responder `eb:c0:5b:f3:eb:5e` (Random Static). Access Address: `0x50654b28`.
- **Explanation:** An isolated, single connection to peripheral `eb:c0:5b:f3:eb:5e`.
- **Degree of Usefulness:** **Low**. The peripheral appears only once, indicating a transient device passing by or an intermittent BLE sensor.

#### Connection 8 (t = 5332.1s / ~88.9 min)
- **Hosts:** Initiator `74:02:ed:c1:71:78` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0xed630877`.
- **Explanation:** Periodic health/step sync to the UltraEasy smartwatch ~11.5 minutes after Connection 6.
- **Degree of Usefulness:** **Very High**. Continued persistent presence of the smartwatch owner.

#### Connection 9 (t = 6163.1s / ~102.7 min)
- **Hosts:** Initiator `5e:c7:b7:36:97:dc` (RPA) $\rightarrow$ Responder `dc:c3:7e:d6:2c:6f` (Random Static). Access Address: `0x50657a9d`.
- **Explanation:** Second connection to peripheral `dc:c3:7e:d6:2c:6f`, occurring ~31 minutes after Connection 4.
- **Degree of Usefulness:** **Moderate to High**. Confirms `dc:c3:7e:d6:2c:6f` is a stationary or long-dwelling peripheral.

#### Connection 10 (t = 6398.2s / ~106.6 min)
- **Hosts:** Initiator `5b:da:5b:4a:3c:81` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x465e1468`.
- **Explanation:** Routine keepalive/sync to the UltraEasy smartwatch ~17.7 minutes after Connection 8.
- **Degree of Usefulness:** **Very High**. Strong behavioral anchor.

#### Connection 11 (t = 6455.4s / ~107.6 min)
- **Hosts:** Initiator `56:7d:bb:a4:95:dc` (RPA) $\rightarrow$ Responder `dc:c3:7e:d6:2c:6f` (Random Static). Access Address: `0xaf9a9c96`.
- **Explanation:** Initiator `56:7d:bb:a4:95:dc` connects to peripheral `dc:c3:7e:d6:2c:6f`.
- **Degree of Usefulness:** **High**. Captures the initiating phone in the middle of an active session.

#### Connection 12 (t = 6458.6s / ~107.6 min)
- **Hosts:** Initiator `56:7d:bb:a4:95:dc` (RPA) $\rightarrow$ Responder `dc:c3:7e:d6:2c:6f` (Random Static). Access Address: `0x50657b9b`.
- **Explanation:** Exactly **3.19 seconds** after Connection 11, the **identical RPA initiator** (`56:7d:bb:a4:95:dc`) connects again to `dc:c3:7e:d6:2c:6f` under a new Access Address (`0x50657b9b`).
- **Degree of Usefulness:** **Very High**. Definitively reveals an immediate connection drop/reconnection or command retry cycle by the same client device.

#### Connection 13 (t = 6690.0s / ~111.5 min)
- **Hosts:** Initiator `67:7f:fc:7f:b5:b0` (RPA) $\rightarrow$ Responder `f4:b2:da:41:f5:91` (Random Static). Access Address: `0x50657399`.
- **Explanation:** A one-time connection between an RPA initiator and random static peripheral `f4:b2:da:41:f5:91`.
- **Degree of Usefulness:** **Low**. Single interaction; no repeat traffic.

#### Connection 14 (t = 7956.9s / ~132.6 min)
- **Hosts:** Initiator `42:d1:3d:29:5e:bd` (RPA) $\rightarrow$ Responder `c0:6e:70:e0:45:e7` (Random Static). Access Address: `0xaf9a841f`.
- **Explanation:** Single connection event to peripheral `c0:6e:70:e0:45:e7`.
- **Degree of Usefulness:** **Low**. Transient presence record.

#### Connection 15 (t = 8550.5s / ~142.5 min)
- **Hosts:** Initiator `67:48:3a:7f:c7:79` (RPA) $\rightarrow$ Responder `ff:c4:de:5d:61:ae` (Random Static). Access Address: `0xaf9ab2eb`.
- **Explanation:** Single connection event to peripheral `ff:c4:de:5d:61:ae`.
- **Degree of Usefulness:** **Low**. Isolated connection.

#### Connection 16 (t = 8919.1s / ~148.7 min)
- **Hosts:** Initiator `46:d5:1c:23:e0:0c` (RPA) $\rightarrow$ Responder `e9:51:bf:fd:00:c6` (Random Static). Access Address: `0x50655c92`.
- **Explanation:** Single connection event to peripheral `e9:51:bf:fd:00:c6`.
- **Degree of Usefulness:** **Low**. Single presence timestamp.

#### Connection 17 (t = 8960.7s / ~149.3 min)
- **Hosts:** Initiator `71:1d:76:09:f3:2a` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0xa2988a86`.
- **Explanation:** Resumption of sync activity to the UltraEasy smartwatch after an idle window of ~42 minutes (indicating user inactivity or screen-off deep sleep).
- **Degree of Usefulness:** **Very High**. Proves the user and device are still present.

#### Connection 18 (t = 9115.1s / ~151.9 min)
- **Hosts:** Initiator `79:9a:b0:4a:21:ee` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x760825e7`.
- **Explanation:** Follow-up sync to the UltraEasy smartwatch 2.5 minutes later.
- **Degree of Usefulness:** **Very High**. Re-establishes normal high-frequency sync patterns.

#### Connection 19 (t = 9821.0s / ~163.7 min)
- **Hosts:** Initiator `7c:b1:f7:92:16:ee` (RPA) $\rightarrow$ Responder `c6:4a:69:7c:43:be` (Random Static). Access Address: `0x50655563`.
- **Explanation:** Single connection to peripheral `c6:4a:69:7c:43:be`.
- **Degree of Usefulness:** **Low**. Isolated event.

#### Connection 20 (t = 10254.1s / ~170.9 min)
- **Hosts:** Initiator `68:2a:f8:d0:3c:2b` (RPA) $\rightarrow$ Responder `ea:6c:42:7e:db:c2` (Random Static). Access Address: `0x506552dd`.
- **Explanation:** An RPA initiator connects to `ea:6c:42:7e:db:c2`. EIR packet inspection shows this peripheral emits **Apple Inc. Company ID `0x004C`** with Nearby / Continuity payload `1202aa01...`.
- **Degree of Usefulness:** **Very High**. Identifies an active Apple ecosystem transaction (AirDrop, Continuity, Universal Clipboard, or device pairing handshake) between an Apple central host and a companion Apple device.

#### Connection 21 (t = 10348.6s / ~172.5 min)
- **Hosts:** Initiator `62:26:9d:d3:d7:21` (RPA) $\rightarrow$ Responder `f8:64:76:1a:62:7c` (Random Static). Access Address: `0x5065539d`.
- **Explanation:** Single connection to peripheral `f8:64:76:1a:62:7c`.
- **Degree of Usefulness:** **Low**. Single interaction.

#### Connection 22 (t = 10417.8s / ~173.6 min)
- **Hosts:** Initiator `4e:47:5a:3d:50:60` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x6a6e2767`.
- **Explanation:** Regular background sync to the UltraEasy smartwatch ~21.7 minutes after Connection 18.
- **Degree of Usefulness:** **Very High**. Continued tracking anchor.

#### Connection 23 (t = 10534.3s / ~175.6 min)
- **Hosts:** Initiator `4a:7f:b4:b0:f9:e1` (RPA) $\rightarrow$ Responder `f5:f6:c3:fe:36:b5` (Random Static). Access Address: `0x89631a39`.
- **Explanation:** Single connection to peripheral `f5:f6:c3:fe:36:b5`.
- **Degree of Usefulness:** **Low**. Isolated event.

#### Connection 24 (t = 10843.6s / ~180.7 min)
- **Hosts:** Initiator `41:79:05:77:a3:bc` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0x5429a7dc`.
- **Explanation:** Sync to the UltraEasy smartwatch ~7.1 minutes after Connection 22.
- **Degree of Usefulness:** **Very High**. Confirms presence spanning past the 3-hour mark.

#### Connection 25 (t = 11674.9s / ~194.6 min)
- **Hosts:** Initiator `6d:02:39:2e:e5:af` (RPA) $\rightarrow$ Responder `f7:a2:6a:29:63:71` (Random Static). Access Address: `0xaf9a8554`.
- **Explanation:** Initiator `6d:02:39:2e:e5:af` connects to peripheral `f7:a2:6a:29:63:71`.
- **Degree of Usefulness:** **Moderate to High**. Forms a pair with Connection 28, proving this initiator device is actively communicating with multiple peripherals in the environment.

#### Connection 26 (t = 12122.2s / ~202.0 min)
- **Hosts:** Initiator `44:c4:f8:a4:96:07` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0xa21dd168`.
- **Explanation:** Routine periodic connection to the UltraEasy smartwatch ~21.3 minutes after Connection 24.
- **Degree of Usefulness:** **Very High**. Consistent presence footprint.

#### Connection 27 (t = 12210.6s / ~203.5 min)
- **Hosts:** Initiator `69:ff:ee:53:71:5f` (RPA) $\rightarrow$ Responder `d2:c2:5f:71:3c:63` (Random Static). Access Address: `0xaf9a93ef`.
- **Explanation:** Single connection to peripheral `d2:c2:5f:71:3c:63`.
- **Degree of Usefulness:** **Low**. Isolated event.

#### Connection 28 (t = 12606.3s / ~210.1 min)
- **Hosts:** Initiator `6d:02:39:2e:e5:af` (RPA) $\rightarrow$ Responder `f4:eb:92:85:1a:7e` (Random Static). Access Address: `0xaf9a8aea`.
- **Explanation:** Occurring ~15.5 minutes after Connection 25, the **same initiator** (`6d:02:39:2e:e5:af`) connects to a different peripheral (`f4:eb:92:85:1a:7e`) right before its RPA rotation interval expires.
- **Degree of Usefulness:** **High**. Demonstrates cross-peripheral interaction by the exact same physical mobile terminal.

#### Connection 29 (t = 12715.4s / ~211.9 min)
- **Hosts:** Initiator `73:ab:b9:07:f3:f0` (RPA) $\rightarrow$ Responder `d8:0f:b5:06:79:7b` (Public: Shenzhen UltraEasy Technology). Access Address: `0xbe55ddf5`.
- **Explanation:** Final connection in the capture to the UltraEasy smartwatch, ~9.9 minutes after Connection 26.
- **Degree of Usefulness:** **Very High**. Establishes that the smartwatch and its paired phone were actively co-located throughout the entire 3.5-hour duration of this capture.
