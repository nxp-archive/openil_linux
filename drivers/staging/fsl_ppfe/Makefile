#
#  Copyright (C) 2007 Freescale Semiconductor, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 

all: modules

modules clean:
	make CROSS_COMPILE=$(CROSS_COMPILE)  ARCH=$(ARCH) -C $(KERNELDIR) M=`pwd` $@

EXTRA_CFLAGS +=  -I$(src)/include  -I$(src) -DCOMCERTO_2000 -DCONFIG_PLATFORM_LS1012A -DGEMAC_MTIP -DCONFIG_UTIL_DISABLED

EXTRA_LDFLAGS += -T$(srctree)/$(src)/control_link.lds

obj-m += pfe.o

pfe-y += pfe_mod.o \
	pfe_hw.o \
	pfe_firmware.o \
	pfe_ctrl.o \
	pfe_ctrl_hal.o \
	pfe_hif.o \
	pfe_hif_lib.o\
	pfe_eth.o \
	pfe_perfmon.o \
	pfe_sysfs.o \
	pfe_debugfs.o \
	pfe_ls1012a_platform.o \
	pfe_hal.o  \

