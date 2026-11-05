include $(TOPDIR)/rules.mk

PKG_NAME:=l2tp-ipsec-client
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/l2tp-ipsec-client
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=VPN
  TITLE:=Managed L2TP/IPsec client (IKEv1 PSK)
  PKGARCH:=all
  DEPENDS:=+strongswan +strongswan-charon +strongswan-swanctl \
	+strongswan-mod-aes +strongswan-mod-sha1 +strongswan-mod-sha2 \
	+strongswan-mod-random +strongswan-mod-hmac +strongswan-mod-kdf \
	+strongswan-mod-openssl +strongswan-mod-kernel-netlink \
	+strongswan-mod-socket-default +strongswan-mod-vici \
	+xl2tpd +ppp +ppp-mod-pppol2tp +ip-full +resolveip +rpcd +jshn \
	+firewall4 +kmod-nft-xfrm
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

define Build/Compile
endef

define Package/l2tp-ipsec-client/install
	$(INSTALL_DIR) $(1)
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,l2tp-ipsec-client))
