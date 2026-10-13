include $(TOPDIR)/rules.mk

PKG_NAME:=mesh-manager
PKG_VERSION:=0.2.0
PKG_RELEASE:=3
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=JiaY-shi <shi05275@163.com>

include $(INCLUDE_DIR)/package.mk

# Full TLS and mesh TLS variants both support 802.11s/SAE and 802.11k/v/r.
# Do not select a second, conflicting wpad when a compatible one is selected.
MESH_WPAD_DEFAULT:=wpad-mesh-openssl
MESH_WPAD_VARIANTS:=$(MESH_WPAD_DEFAULT) wpad-mesh-mbedtls wpad-mesh-wolfssl wpad-openssl wpad-mbedtls wpad-wolfssl
MESH_WPAD_CONDITION:=$(subst $(space),||,$(strip $(foreach pkg,$(MESH_WPAD_VARIANTS),PACKAGE_$(pkg))))
# Let the firmware select one compatible provider. Conditional selects of wpad
# alternatives create Kconfig cycles through hostapd's mutual conflicts.
MESH_WPAD_DEPENDS:=@($(MESH_WPAD_CONDITION))
PKG_CONFIG_DEPENDS+=$(foreach pkg,$(MESH_WPAD_VARIANTS),CONFIG_PACKAGE_$(pkg))

# Metadata scans run without .config. At packaging time, record exactly the
# selected provider (prefer built-in over module), including full wpad variants
# which do not provide OpenWrt's virtual "wpad-mesh" package.
ifndef DUMP
  MESH_WPAD_SELECTED:=$(firstword $(foreach mode,y m,$(foreach pkg,$(MESH_WPAD_VARIANTS),$(if $(filter $(mode),$(CONFIG_PACKAGE_$(pkg))),$(pkg)))))
  MESH_WPAD_DEPENDS:=+$(or $(MESH_WPAD_SELECTED),$(MESH_WPAD_DEFAULT))
endif

define Package/mesh-manager
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Local Mesh configuration and recovery service
  DEPENDS:=+libopenssl +procd \
	+@PACKAGE_rpcd +rpcd-mod-ucode +rpcd-mod-iwinfo +umdns +ip-full +ip-bridge \
	+iw +wifi-scripts +uci +jsonfilter +dnsmasq +firewall4 +odhcpd-ipv6only \
	+usteer $(MESH_WPAD_DEPENDS) +busybox \
	+@BUSYBOX_CONFIG_UDHCPC +@BUSYBOX_CONFIG_PING +@BUSYBOX_CONFIG_FEATURE_FANCY_PING \
	+@BUSYBOX_CONFIG_TRACEROUTE \
	+@BUSYBOX_CONFIG_SLEEP +@BUSYBOX_CONFIG_SYNC
endef

define Package/mesh-manager/description
  Independent local controller/AP intent compiler with explicit takeover,
  persistent transactions, drift detection and guarded rollback.
  Device identities, authorized pairing and distributed configuration transactions.
  Firmware builds require one mesh-capable wpad TLS variant from WirelessAPD.
  Experimental development version; consult the acceptance test matrix.
endef

define Package/mesh-manager/conffiles
/etc/config/mesh-manager
/etc/mesh-manager/
endef

define Build/Prepare
	$(INSTALL_DIR) $(PKG_BUILD_DIR)
	$(CP) ./src/*.c $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/mesh-manager-store $(PKG_BUILD_DIR)/store.c
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/mesh-manager-arp-probe $(PKG_BUILD_DIR)/arp_probe.c
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/mesh-manager-dns-probe $(PKG_BUILD_DIR)/dns_probe.c
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/mesh-manager-radio-info $(PKG_BUILD_DIR)/radio_info.c -liwinfo
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -Wall -Wextra -Werror $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/mesh-manager-channel $(PKG_BUILD_DIR)/channel.c $(PKG_BUILD_DIR)/probe.c -lssl -lcrypto -ljson-c
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror -shared -fPIC \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/mesh_crypto.so $(PKG_BUILD_DIR)/crypto.c -lucode -lcrypto
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror -shared -fPIC \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/mesh_process.so $(PKG_BUILD_DIR)/process.c -lucode -lubox
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror -shared -fPIC \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/mesh_data.so $(PKG_BUILD_DIR)/data.c -lucode
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror -shared -fPIC \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/mesh_enrollment_runtime.so $(PKG_BUILD_DIR)/enrollment_runtime.c -lucode
	$(TARGET_CC) $(TARGET_CPPFLAGS) $(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include -Wall -Wextra -Werror -shared -fPIC \
		$(TARGET_LDFLAGS) -o $(PKG_BUILD_DIR)/mesh_onboard.so $(PKG_BUILD_DIR)/onboard.c -lucode -lcrypto
endef

define Package/mesh-manager/install
	$(CP) ./files/* $(1)/
	$(INSTALL_DIR) $(1)/usr/libexec
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh-manager-store $(1)/usr/libexec/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh-manager-arp-probe $(1)/usr/libexec/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh-manager-dns-probe $(1)/usr/libexec/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh-manager-radio-info $(1)/usr/libexec/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh-manager-channel $(1)/usr/libexec/
	$(INSTALL_DIR) $(1)/usr/lib/ucode
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh_crypto.so $(1)/usr/lib/ucode/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh_process.so $(1)/usr/lib/ucode/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh_data.so $(1)/usr/lib/ucode/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh_enrollment_runtime.so $(1)/usr/lib/ucode/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mesh_onboard.so $(1)/usr/lib/ucode/
	chmod 0755 $(1)/etc/init.d/mesh-manager $(1)/usr/sbin/mesh-manager
	chmod 0755 $(1)/usr/sbin/mesh-manager-agent $(1)/usr/sbin/mesh-manager-backhaul \
		$(1)/usr/sbin/mesh-manager-enrollment $(1)/usr/libexec/mesh-manager-peer $(1)/usr/libexec/mesh-manager-onboard-dhcp
	chmod 0755 $(1)/usr/libexec/mesh-manager-rpc-worker $(1)/usr/libexec/mesh-manager-radio-regulatory \
		$(1)/usr/libexec/mesh-manager-wireless-features $(1)/usr/libexec/mesh-manager-onboard-worker
endef

$(eval $(call BuildPackage,mesh-manager))
