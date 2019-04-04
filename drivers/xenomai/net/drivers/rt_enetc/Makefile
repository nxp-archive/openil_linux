# SPDX-License-Identifier: GPL-2.0
ccflags-y += -Idrivers/xenomai/net/stack/include
obj-$(CONFIG_XENO_DRIVERS_NET_DRV_ENETC) += rt_enetc.o
rt_enetc-$(CONFIG_XENO_DRIVERS_NET_DRV_ENETC) += enetc.o enetc_cbdr.o
rt_enetc-$(CONFIG_PCI_IOV) += enetc_msg.o
rt_enetc-objs := enetc_pf.o enetc_mdio.o $(rt_enetc-y)

