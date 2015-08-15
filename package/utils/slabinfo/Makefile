#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=slabinfo
PKG_RELEASE:=$(LINUX_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/slabinfo
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=slabinfo tools utility
  VERSION:=$(LINUX_VERSION)-$(PKG_RELEASE)
  URL:=http://www.kernel.org
  MAINTAINER:=Florian Fainelli <florian@openwrt.org>
endef

define Package/slabinfo/description
  slabinfo tools utility.
endef

define Build/Prepare
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -o $(PKG_BUILD_DIR)/slabinfo \
		$(LINUX_DIR)/tools/vm/slabinfo.c
endef

define Package/slabinfo/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/slabinfo $(1)/sbin/
endef

$(eval $(call BuildPackage,slabinfo))
