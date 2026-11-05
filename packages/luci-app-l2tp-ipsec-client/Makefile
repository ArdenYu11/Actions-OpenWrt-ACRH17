include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-l2tp-ipsec-client
PKG_VERSION:=1.3.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-l2tp-ipsec-client
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for the managed L2TP/IPsec client
  PKGARCH:=all
  DEPENDS:=+luci-base +l2tp-ipsec-client
endef

define Build/Compile
endef

define Package/luci-app-l2tp-ipsec-client/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || /etc/init.d/rpcd reload
exit 0
endef

define Package/luci-app-l2tp-ipsec-client/install
	$(INSTALL_DIR) $(1)/www
	$(CP) ./htdocs/* $(1)/www/
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,luci-app-l2tp-ipsec-client))
