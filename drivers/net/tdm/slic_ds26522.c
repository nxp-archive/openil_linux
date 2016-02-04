/*
 * drivers/tdm/line_ctrl/slic_ds26522.c
 *
 * Copyright (C) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 * SLIC Line Control Module for maxim SLICs.
 * This  is a slic control and initialization module.
 *
 * Author:Zhao Qiang<B45475@freescale.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This driver was created solely by Freescale, without the assistance,
 * support or intellectual property of Maxim Semiconductor.  No maintenance
 * or support will be provided by Maxim Semiconductor regarding this driver
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/spi/spi.h>
#include <linux/wait.h>
#include <linux/param.h>
#include <linux/delay.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include "slic_ds26522.h"

#define DRV_DESC "FREESCALE DEVELOPED MAXIM SLIC DRIVER"
#define DRV_NAME "ds26522"

#define MAX_NUM_OF_SLICS 10
#define SLIC_TRANS_LEN 1
#define SLIC_TWO_LEN 2
#define SLIC_THREE_LEN 3

#define CPLD_MISCCSR	0x17
#define SPI_CS3_SEL0	0x00
#define SPI_CS3_SEL1	0x80

#define TESTING_PRODUCT_CODE

static struct spi_device *g_spi;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhao Qiang<B45475@freescale.com>");
MODULE_DESCRIPTION(DRV_DESC);

static unsigned int addr_swap(unsigned int addr)
{
	addr = ((addr & 0x3f80) >> 7) | ((addr & 0x7F) << 7);
	addr = ((addr & 0x3870) >> 4) | ((addr & 0x387) << 4) | (addr & 0x408);
	addr = ((addr & 0x2244) >> 2) | ((addr & 0x891) << 2) | (addr & 0x152a);
	return addr;
}

static unsigned char data_swap(unsigned char data)
{
	data = ((data & 0xF0) >> 4) | ((data & 0x0F) << 4);
	data = ((data & 0xcc) >> 2) | ((data & 0x33) << 2);
	data = ((data & 0xaa) >> 1) | ((data & 0x55) << 1);
	return data;
}

static void slic_write(struct spi_device *spi, unsigned int addr,
		       unsigned char data)
{
	char temp[3];

	addr = addr_swap(addr);
	data = data_swap(data);
	temp[0] = (unsigned char)((addr >> 7) & 0x7f);
	temp[1] = (unsigned char)((addr << 1) & 0xfe);
	temp[2] = data;

	/* write spi addr and value */
	spi_write(spi, &temp[0], SLIC_THREE_LEN);
}

static unsigned char slic_read(struct spi_device *spi, unsigned int addr)
{
	int ret;
	unsigned char temp[2];
	unsigned char data;

	addr = addr_swap(addr);
	temp[0] = (unsigned char)(((addr >> 7) & 0x7f) | 0x80);
	temp[1] = (unsigned char)((addr << 1) & 0xfe);

	ret = spi_write_then_read(spi, &temp[0], SLIC_TWO_LEN, &data,
				  SLIC_TRANS_LEN);
	if (ret < 0)
		return ret;

	data = data_swap(data);
	return data;
}

static bool get_slic_product_code(struct spi_device *spi)
{
	unsigned char device_id;

	device_id = slic_read(spi, DS26522_IDR_ADDR);
	if ((device_id & 0xf8) == 0x68) {
		pr_info("The Device is DS26522.\n");
		return true;
	}

	pr_info("The Device isn't DS26522.\n");
	return false;
}

static void ds26522_e1_spec_config(struct spi_device *spi)
{
	/* Receive E1 Mode (Receive Master Mode Register - RMMR)
	 * Framer Disabled
	 */
	slic_write(spi, DS26522_RMMR_ADDR, DS26522_RMMR_E1);
	/* Transmit E1 Mode (Transmit Master Mode Register - TMMR)
	 * Framer Disable
	 */
	slic_write(spi, DS26522_TMMR_ADDR, DS26522_TMMR_E1);
	/* Receive E1 Mode Framer Enable (RMMR - Framer Enabled/E1) */
	slic_write(spi, DS26522_RMMR_ADDR,
		   DS26522_RMMR_FRM_EN | DS26522_RMMR_E1);
	/* Transmit E1 Mode Framer Enable (TMMR - Framer Enabled/E1) */
	slic_write(spi, DS26522_TMMR_ADDR,
		   DS26522_TMMR_FRM_EN | DS26522_TMMR_E1);
	/* RCR1, receive E1 B8zs & ESF (Receive Control Register 1 - E1 MODE) */
	slic_write(spi, DS26522_RCR1_ADDR,
		   DS26522_RCR1_E1_HDB3 | DS26522_RCR1_E1_CCS);
	/* RIOCR (RSYSCLK=2.048MHz, RSYNC-Output) */
	slic_write(spi, DS26522_RIOCR_ADDR,
		   DS26522_RIOCR_2048KHZ | DS26522_RIOCR_RSIO_OUT);
	/* TCR1 Transmit E1 b8zs */
	slic_write(spi, DS26522_TCR1_ADDR, DS26522_TCR1_TB8ZS);
	/* TIOCR (TSYSCLK=2.048MHz, TSYNC-Output) */
	slic_write(spi, DS26522_TIOCR_ADDR,
		   DS26522_TIOCR_2048KHZ | DS26522_TIOCR_TSIO_OUT);
	/* Set E1TAF (Transmit Align Frame Register regsiter) */
	slic_write(spi, DS26522_E1TAF_ADDR, DS26522_E1TAF_DEFAULT);
	/* Set E1TNAF register (Transmit Non-Align Frame Register) */
	slic_write(spi, DS26522_E1TNAF_ADDR, DS26522_E1TNAF_DEFAULT);
	/* Receive E1 Mode Framer Enable & init Done (RMMR) */
	slic_write(spi, DS26522_RMMR_ADDR,
		   DS26522_RMMR_FRM_EN |
		   DS26522_RMMR_INIT_DONE |
		   DS26522_RMMR_E1);
	/* Transmit E1 Mode Framer Enable & init Done (TMMR) */
	slic_write(spi, DS26522_TMMR_ADDR,
		   DS26522_TMMR_FRM_EN |
		   DS26522_TMMR_INIT_DONE |
		   DS26522_TMMR_E1);
	/* Configure LIU (LIU Transmit Receive Control Register
	 * - LTRCR. E1 mode)
	 */
	slic_write(spi, DS26522_LTRCR_ADDR, DS26522_LTRCR_E1);
	/* E1 Mode default 75 ohm w/Transmit Impedance Matlinking
	 * (LIU Transmit Impedance and Pulse Shape Selection Register - LTITSR)
	 */
	slic_write(spi, DS26522_LTITSR_ADDR,
		   DS26522_LTITSR_TLIS_75OHM | DS26522_LTITSR_LBOS_75OHM);
	/* E1 Mode default 75 ohm Long Haul w/Receive Impedance Matlinking
	 * (LIU Receive Impedance and Sensitivity Monitor Register - LRISMR)
	 */
	slic_write(spi, DS26522_LRISMR_ADDR,
		   DS26522_LRISMR_75OHM | DS26522_LRISMR_MAX);
	/* Enable Transmit output (LIU Maintenance Control Register - LMCR) */
	slic_write(spi, DS26522_LMCR_ADDR, DS26522_LMCR_TE);
}

static int slic_ds26522_init_configure(unsigned char *device_handle,
				     struct spi_device *spi)
{
	unsigned int addr;

	/* set clock */
	slic_write(spi, DS26522_GTCCR_ADDR, DS26522_GTCCR_BPREFSEL_REFCLKIN |
			DS26522_GTCCR_BFREQSEL_2048KHZ |
			DS26522_GTCCR_FREQSEL_2048KHZ);
	slic_write(spi, DS26522_GTCR2_ADDR, DS26522_GTCR2_TSSYNCOUT);
	slic_write(spi, DS26522_GFCR_ADDR, DS26522_GFCR_BPCLK_2048KHZ);

	/* set gtcr */
	slic_write(spi, DS26522_GTCR1_ADDR, DS26522_GTCR1);

	/* Global LIU Software Reset Register (GLSRR) */
	slic_write(spi, DS26522_GLSRR_ADDR, DS26522_GLSRR_RESET);
	/* Global Framer and BERT Software Reset Register (GFSRR) */
	slic_write(spi, DS26522_GFSRR_ADDR, DS26522_GFSRR_RESET);

	usleep_range(100, 120);

	slic_write(spi, DS26522_GLSRR_ADDR, DS26522_GLSRR_NORMAL);
	slic_write(spi, DS26522_GFSRR_ADDR, DS26522_GFSRR_NORMAL);

	/* Perform RX/TX SRESET,Reset receiver (RMMR) */
	slic_write(spi, DS26522_RMMR_ADDR, DS26522_RMMR_SFTRST);
	/* Reset tranceiver (TMMR) */
	slic_write(spi, DS26522_TMMR_ADDR, DS26522_TMMR_SFTRST);

	usleep_range(100, 120);

	/* Zero all Framer Registers */
	for (addr = DS26522_RF_ADDR_START; addr <= DS26522_RF_ADDR_END;
			addr++) {
		slic_write(spi, addr, 0);
	}

	for (addr = DS26522_TF_ADDR_START; addr <= DS26522_TF_ADDR_END;
			addr++) {
		slic_write(spi, addr, 0);
	}

	for (addr = DS26522_LIU_ADDR_START; addr <= DS26522_LIU_ADDR_END;
			addr++) {
		slic_write(spi, addr, 0);
	}

	for (addr = DS26522_BERT_ADDR_START; addr <= DS26522_BERT_ADDR_END;
			addr++) {
		slic_write(spi, addr, 0);
	}

	/*enable loopback mode*/
	/*slic_write(spi, DS26522_RMMR_ADDR, DS26522_RCR3_FLB);*/

	/* setup ds26522 for E1 specification */
	ds26522_e1_spec_config(spi);

	slic_write(spi, DS26522_GTCR1_ADDR, 0x00);

	return 0;
}

static int slic_ds26522_remove(struct spi_device *spi)
{
	pr_info("SLIC module uninstalled\n");
	return 0;
}

static int slic_ds26522_probe(struct spi_device *spi)
{
	int ret = 0;
	unsigned char *device_handle;

	g_spi = spi;
	spi->bits_per_word = 8;

	if (!get_slic_product_code(spi))
		return ret;

	device_handle = 0x0;

	ret = slic_ds26522_init_configure(device_handle, spi);
	if (ret == 0)
		pr_info("SLIC0 configuration success\n");
	else
		pr_info("%s slic0 configuration failed\n", __func__);

	return ret;
}

static const struct of_device_id slic_ds26522_match[] = {
	{
	 .compatible = "maxim,ds26522",
	 },
	{},
};

static struct spi_driver slic_ds26522_driver = {
	.driver = {
		   .name = "ds26522",
		   .bus = &spi_bus_type,
		   .owner = THIS_MODULE,
		   .of_match_table = slic_ds26522_match,
		   },
	.probe = slic_ds26522_probe,
	.remove = slic_ds26522_remove,

};

static int __init slic_ds26522_init(void)
{
	int ret;

	pr_info("SLIC: " DRV_DESC "\n");
	pr_info("####################################################");
	pr_info("\n# This driver was created solely by Freescale,   #");
	pr_info("\n# without the assistance, support or intellectual#");
	pr_info("\n# property of Maxim Semiconductor. No            #");
	pr_info("\n# maintenance or support will be provided by     #");
	pr_info("\n# Maxim  Semiconductor regarding this driver.    #");
	pr_info("\n##################################################");
	pr_info("\n");

	ret = spi_register_driver(&slic_ds26522_driver);
	if (ret != 0)
		pr_info("%s spi_register_driver failed\n", __func__);
	return ret;
}

static void __exit slic_ds26522_exit(void)
{
	spi_unregister_driver(&slic_ds26522_driver);
}

module_init(slic_ds26522_init);
module_exit(slic_ds26522_exit);
