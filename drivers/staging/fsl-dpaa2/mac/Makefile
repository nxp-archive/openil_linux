
obj-$(CONFIG_FSL_DPAA2_FIXED_PHY_HACK) += fixed.o
obj-$(CONFIG_FSL_DPAA2_PHY_PROXY) += dpaa2_ppx.o

dpaa2_ppx-objs := phy_proxy.o dpmac.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
