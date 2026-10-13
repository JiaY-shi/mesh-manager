# Mesh Manager for OpenWrt

Mesh management and 802.11k/v/r roaming configuration using OpenWrt's native
wireless components and usteer, with a compact LuCI interface. AP routers can
join over Ethernet or wirelessly using the controller's Wi-Fi name and password.

## English

These APK packages are built with the current OpenWrt snapshot SDK. Use them
only with APK-based firmware that has a compatible architecture and package ABI.
They cannot be installed on firmware using opkg/IPK.

Check your router's package architecture:

```sh
apk --print-arch
```

Download the three files for that architecture:

- `mesh-manager-<architecture>.apk`: Mesh management backend.
- `luci-app-mesh-manager-<architecture>.apk`: LuCI interface.
- `luci-i18n-mesh-manager-zh-cn-<architecture>.apk`: Simplified Chinese translation.

Download `sha256sums-<architecture>.txt` as well. Verify the files on your computer
from the download directory:

```sh
sha256sum --check 'sha256sums-<architecture>.txt'
```

Replace `<architecture>` with the value reported by the router. Upload the three
APK files to `/tmp/` on the router, then install them:

```sh
apk add --allow-untrusted /tmp/mesh-manager-*.apk \
  /tmp/luci-app-mesh-manager-*.apk \
  /tmp/luci-i18n-mesh-manager-zh-cn-*.apk
```

Keep the firmware's package repositories available so APK can resolve the
dependencies. Full LuCI and one Mesh/SAE-capable wpad variant are required;
replace a basic wpad variant with a compatible one before installation.
Refresh LuCI and open **Network → Mesh Manager** to configure the controller
or join an AP. See the repository README for setup instructions.

## 中文说明

本 Release 使用当前 OpenWrt snapshot SDK 构建 APK 软件包。设备固件需使用
APK 包管理器，并与软件包的架构及 ABI 兼容；不适用于使用 opkg/IPK 的固件。

在路由器上查看软件包架构：

```sh
apk --print-arch
```

下载与该架构对应的三个文件：

- `mesh-manager-<架构>.apk`：Mesh 管理后台。
- `luci-app-mesh-manager-<架构>.apk`：LuCI 管理界面。
- `luci-i18n-mesh-manager-zh-cn-<架构>.apk`：LuCI 简体中文翻译。

同时下载 `sha256sums-<架构>.txt`，在电脑上的下载目录校验文件：

```sh
sha256sum --check 'sha256sums-<架构>.txt'
```

将 `<架构>` 替换为路由器输出的实际架构。把三个 APK 文件上传到路由器
的 `/tmp/` 目录，然后安装：

```sh
apk add --allow-untrusted /tmp/mesh-manager-*.apk \
  /tmp/luci-app-mesh-manager-*.apk \
  /tmp/luci-i18n-mesh-manager-zh-cn-*.apk
```

保留可用的固件软件源，以便 APK 自动安装依赖。设备需包含完整 LuCI，
并安装一种支持 Mesh/SAE 的 wpad；安装前先将基础版 wpad 替换为兼容变体。
安装后刷新 LuCI，进入 **网络 → Mesh管理** 创建主节点或让 AP 加入。
详细配置步骤见仓库 README。
