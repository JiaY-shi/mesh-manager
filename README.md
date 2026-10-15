# Mesh Manager

**English** | [简体中文](README.zh-CN.md)

Mesh management for OpenWrt, built on its native wireless components, usteer,
and 802.11k/v/r. Set up a network, configure Wi-Fi, and manage AP routers
through a compact LuCI interface.

Each Mesh network has one controller and multiple AP routers. APs can join
over Ethernet or wirelessly using the controller's Wi-Fi name and password.

## Features

- Centralized Wi-Fi names, passwords, and 802.11k/v/r roaming configuration.
- Client roaming assistance using OpenWrt's official usteer.
- Wired and 802.11s wireless backhaul, with wired priority and wireless standby.
- Automatic controller discovery, enrollment, and configuration synchronization.
- Network topology, node status, backhaul quality, clients, and change history.
- Configuration previews and automatic rollback when health confirmation fails.
- Automatic Guest VLAN and subnet allocation, with separate credentials and access policies.
- Restore original managed settings when disabling Mesh and rejoin after leaving.

## Installation

### Requirements

- An OpenWrt build environment matching your target device; the device firmware
  must include full LuCI.
- Both `mesh-manager` and `luci-app-mesh-manager` on the controller and each AP.
- For wireless backhaul, a wireless chipset and driver supporting 802.11s,
  SAE, and concurrent AP and Mesh interfaces.

### Add the feed and build

Add the following line to the active feed configuration in your OpenWrt build
directory: use `feeds.conf`, or `feeds.conf.default` if `feeds.conf` does not
exist.

```text
src-git mesh_manager https://github.com/JiaY-shi/mesh-manager.git
```

Run these commands from the build directory:

```sh
./scripts/feeds update -a
./scripts/feeds install -p mesh_manager mesh-manager luci-app-mesh-manager
./scripts/feeds install -a
make menuconfig
```

Select your target device and the packages you need:

| Package | Purpose |
| --- | --- |
| `mesh-manager` | Mesh management backend |
| `luci-app-mesh-manager` | LuCI management interface |
| `luci` | Full LuCI, if not already included in the firmware |
| `luci-i18n-mesh-manager-zh-cn` | Optional Simplified Chinese translation |

Select one wpad variant supporting Mesh/SAE and 802.11k/v/r, such as
`wpad-mesh-openssl` or `wpad-mesh-mbedtls`. Include only one wpad variant,
replacing `wpad-basic-*` or `wpad-mini` with a fully featured variant.

Select packages as `[*]` to include them in the firmware, then build:

```sh
make -j$(nproc)
```

The resulting firmware includes the selected packages. For an SDK build or
standalone packages, select the packages as `<M>` and build them individually:

```sh
make package/feeds/mesh_manager/mesh-manager/compile V=s
make package/feeds/mesh_manager/luci-app-mesh-manager/compile V=s
```

Standalone packages must match the device architecture and running firmware.
Install them with the firmware's package manager and include their dependencies.
Refresh LuCI after installation.

## Usage

### Create a controller

1. Log in to the router you want to use as the controller and open
   **Network → Mesh Manager**.
2. Select **Create controller** and enter a Wi-Fi name and password.
   Choose router or bridge mode for your network and retain the current
   controller LAN address.
3. Click **Create and enable Mesh**, review the configuration preview,
   and confirm the changes.
4. For wireless APs, open **Backhaul**, select **802.11s wireless** or
   **Wired preferred, wireless standby**, configure a channel and width
   supported by every node, and confirm the changes.

The controller needs a correct system clock. Configure the backhaul before
joining AP routers.

### Join an AP over Ethernet

1. Connect the AP's uplink port, usually its WAN port, to a controller LAN port.
2. Log in to the AP and open **Network → Mesh Manager → Request to join**.
3. Leave the bootstrap Wi-Fi name and password empty and click **Join Mesh**.
4. Wait for discovery, configuration synchronization, and health confirmation.

### Join an AP wirelessly

1. Ensure that Mesh and wireless backhaul are enabled on the controller.
2. Log in to the AP and open **Network → Mesh Manager → Request to join**.
3. Enter the controller's Wi-Fi name and password and click **Join Mesh**.
   If several access points share that name, select the intended controller's
   access point.
4. Wait for the wireless connection, configuration synchronization, and health
   confirmation to complete.

An AP's management address may change after joining. Find its address under
**Overview → Network topology** on the controller. Only routers running this
software and requesting enrollment become managed APs; phones and computers
continue connecting as ordinary Wi-Fi clients.

### Manage nodes and leave a network

- Use **Wireless** on the controller to change Wi-Fi and roaming settings,
  and **Backhaul** to change backhaul settings. Review and confirm the preview
  after saving.
- Before changing the backhaul mode, channel, width, or credentials, connect
  every AP over Ethernet and follow the maintenance instructions in the UI.
- Manage APs under **Nodes**, and use **Clients**, **Changes**, and **Diagnostics**
  to inspect connections, operation results, and network checks.
- To pause an AP, choose **Disable Mesh** and wait for its original managed
  settings to be restored and confirmed. Its identity remains bound, allowing
  you to resume with **Enable Mesh**.
- To leave completely, disable Mesh on the AP, confirm restoration, and then
  revoke its identity on the controller. The AP can request to join again.
- Before disabling Mesh on the controller, disable every AP and confirm that
  its configuration has been restored.

After restoration, access the device at its original LAN management address.
Resolve any reported external configuration conflicts before continuing.

802.11k/v/r behavior depends on client support; clients decide when to roam.

### Guest networks

On the controller, open **Wireless → Advanced settings** to enable Guest and set
a separate password. Use `auto` for VLAN and subnet allocation, or select an
unused VLAN and a private `/24` subnet with gateway address `.1`. Guest requires
a managed routing gateway, which provides DHCP and firewall policies; APs
transparently carry its tagged traffic.

Guest defaults to Internet access, client isolation on the same AP, and restricted
access to the main LAN. You can disable Internet access or client isolation,
allow mutual LAN access, or allow selected LAN-to-Guest service ports. Write
port exceptions as `TCP:80,443;UDP:123`.

## License

GPL-2.0-only.
