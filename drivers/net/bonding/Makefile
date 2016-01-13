#
# Makefile for the Ethernet Bonding driver
#

include $(srctree)/drivers/net/ethernet/freescale/sdk_fman/ncsw_config.mk
ccflags-y += \
	-I$(srctree)/drivers/net/ethernet/freescale/sdk_dpa \
	-I$(srctree)/drivers/net/ethernet/freescale/sdk_fman/src/wrapper \
	-I$(srctree)/drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/Pcd \
	-I$(srctree)/drivers/net/ethernet/freescale/sdk_fman/Peripherals/FM/inc

obj-$(CONFIG_BONDING) += bonding.o

bonding-objs := bond_main.o bond_3ad.o bond_alb.o bond_sysfs.o bond_sysfs_slave.o bond_debugfs.o bond_netlink.o bond_options.o

proc-$(CONFIG_PROC_FS) += bond_procfs.o
bonding-objs += $(proc-y)

hash_pcd_based_xmit_frames_distribution-$(CONFIG_HW_DISTRIBUTION_WITH_OH) += \
	hw_distribution.o hw_oh_pcd.o

bonding-objs += $(hash_pcd_based_xmit_frames_distribution-y)
