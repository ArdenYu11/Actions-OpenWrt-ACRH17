include $(TOPDIR)/rules.mk

PKG_NAME:=l2tp-ipsec-client
PKG_VERSION:=1.3.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/l2tp-ipsec-client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Managed L2TP/IPsec client (IKEv1 PSK)
  DEPENDS:=+strongswan +strongswan-charon +strongswan-swanctl \
	+strongswan-mod-aes +strongswan-mod-sha1 +strongswan-mod-sha2 \
	+strongswan-mod-random +strongswan-mod-hmac +strongswan-mod-kdf \
	+strongswan-mod-openssl +strongswan-mod-kernel-netlink \
	+strongswan-mod-socket-default +strongswan-mod-vici \
	+xl2tpd +ppp +ppp-mod-pppol2tp +ip-full +resolveip +rpcd +jshn \
	+firewall4 +kmod-nft-xfrm +kmod-nft-nat +unshare
endef

define Package/l2tp-ipsec-client/conffiles
/etc/config/l2tpipsec
endef

define Package/l2tp-ipsec-client/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	(. /etc/uci-defaults/90-l2tp-ipsec-client) && rm -f /etc/uci-defaults/90-l2tp-ipsec-client
}
exit 0
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Wall -Wextra -Werror -o $(PKG_BUILD_DIR)/domain-dns $(PKG_BUILD_DIR)/domain-dns.c $(TARGET_LDFLAGS)
endef

define Package/l2tp-ipsec-client/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/domain-dns $(1)/usr/lib/l2tp-ipsec-client/domain-dns
endef

$(eval $(call BuildPackage,l2tp-ipsec-client))
