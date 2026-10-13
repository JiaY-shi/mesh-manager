# Copyright (C) 2018-2019 Lienol
#
# This is free software, licensed under the Apache License, Version 2.0 .
#
include $(TOPDIR)/rules.mk


PKG_NAME:=luci-app-mesh-manager

LUCI_TITLE:=LuCI Mesh Manager
LUCI_DEPENDS:=+luci-base +mesh-manager
LUCI_PKGARCH:=all
PKG_VERSION:=0.2.0
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=JiaY-shi <shi05275@163.com>
LUCI_MAINTAINER:=JiaY-shi <shi05275@163.com>

# These are public LuCI assets. Minifiers may inherit a private build umask;
# normalize only this application's assets, including offline image installs.
define Package/luci-app-mesh-manager/postinst
#!/bin/sh
for directory in "$${IPKG_INSTROOT}/www/luci-static/resources/mesh_manager" "$${IPKG_INSTROOT}/www/luci-static/resources/view/mesh-manager"; do
	[ -d "$$directory" ] || continue
	find "$$directory" -type d -exec chmod 0755 {} \;
	find "$$directory" -type f -exec chmod 0644 {} \;
done
[ -n "$${IPKG_INSTROOT}" ] || {
	rm -f /tmp/luci-indexcache.*
	rm -rf /tmp/luci-modulecache/
	/etc/init.d/rpcd reload 2>/dev/null
}
exit 0
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
