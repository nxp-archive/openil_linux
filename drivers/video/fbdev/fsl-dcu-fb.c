/*
 * Copyright 2012-2014 Freescale Semiconductor, Inc.
 *
 * Freescale DCU framebuffer device driver
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/fb.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/regmap.h>
#include <linux/uaccess.h>
#include <video/of_display_timing.h>
#include <video/videomode.h>

#define DRIVER_NAME			"fsl-dcu-fb"

#define DCU_DCU_MODE			0x10
#define DCU_MODE_BLEND_ITER(x)		((x) << 20)
#define DCU_MODE_RASTER_EN		BIT(14)
#define DCU_MODE_DCU_MODE(x)		(x)
#define DCU_MODE_DCU_MODE_MASK		0x03
#define DCU_MODE_OFF			0
#define DCU_MODE_NORMAL			1
#define DCU_MODE_TEST			2
#define DCU_MODE_COLORBAR		3

#define DCU_BGND			0x14
#define DCU_BGND_R(x)			((x) << 16)
#define DCU_BGND_G(x)			((x) << 8)
#define DCU_BGND_B(x)			(x)

#define DCU_DISP_SIZE			0x18
#define DCU_DISP_SIZE_DELTA_Y(x)	((x) << 16)
#define DCU_DISP_SIZE_DELTA_X(x)	(x)

#define DCU_HSYN_PARA			0x1c
#define DCU_HSYN_PARA_BP(x)		((x) << 22)
#define DCU_HSYN_PARA_PW(x)		((x) << 11)
#define DCU_HSYN_PARA_FP(x)		(x)

#define DCU_VSYN_PARA			0x20
#define DCU_VSYN_PARA_BP(x)		((x) << 22)
#define DCU_VSYN_PARA_PW(x)		((x) << 11)
#define DCU_VSYN_PARA_FP(x)		(x)

#define DCU_SYN_POL			0x24
#define DCU_SYN_POL_INV_PXCK_FALL	(0 << 6)
#define DCU_SYN_POL_NEG_REMAIN		(0 << 5)
#define DCU_SYN_POL_INV_VS_LOW		BIT(1)
#define DCU_SYN_POL_INV_HS_LOW		BIT(0)

#define DCU_THRESHOLD			0x28
#define DCU_THRESHOLD_LS_BF_VS(x)	((x) << 16)
#define DCU_THRESHOLD_OUT_BUF_HIGH(x)	((x) << 8)
#define DCU_THRESHOLD_OUT_BUF_LOW(x)	(x)

#define DCU_INT_STATUS			0x2C
#define DCU_INT_STATUS_UNDRUN		BIT(1)

#define DCU_INT_MASK			0x30
#define DCU_INT_MASK_UNDRUN		BIT(1)
#define DCU_INT_MASK_ALL		0xffffffff

#define DCU_DIV_RATIO			0x54

#define DCU_UPDATE_MODE			0xcc
#define DCU_UPDATE_MODE_MODE		BIT(31)
#define DCU_UPDATE_MODE_READREG		BIT(30)

#define DCU_CTRLDESCLN_1(x)		(0x200 + (x) * 0x40)
#define DCU_CTRLDESCLN_1_HEIGHT(x)	((x) << 16)
#define DCU_CTRLDESCLN_1_WIDTH(x)	(x)

#define DCU_CTRLDESCLN_2(x)		(0x204 + (x) * 0x40)
#define DCU_CTRLDESCLN_2_POSY(x)	((x) << 16)
#define DCU_CTRLDESCLN_2_POSX(x)	(x)

#define DCU_CTRLDESCLN_3(x)		(0x208 + (x) * 0x40)

#define DCU_CTRLDESCLN_4(x)		(0x20c + (x) * 0x40)
#define DCU_CTRLDESCLN_4_EN		BIT(31)
#define DCU_CTRLDESCLN_4_TILE_EN	BIT(30)
#define DCU_CTRLDESCLN_4_DATA_SEL_CLUT	BIT(29)
#define DCU_CTRLDESCLN_4_SAFETY_EN	BIT(28)
#define DCU_CTRLDESCLN_4_TRANS(x)	((x) << 20)
#define DCU_CTRLDESCLN_4_BPP(x)		((x) << 16)
#define DCU_CTRLDESCLN_4_RLE_EN		BIT(15)
#define DCU_CTRLDESCLN_4_LUOFFS(x)	((x) << 4)
#define DCU_CTRLDESCLN_4_BB_ON		BIT(2)
#define DCU_CTRLDESCLN_4_AB(x)		(x)

#define DCU_CTRLDESCLN_5(x)		(0x210 + (x) * 0x40)
#define DCU_CTRLDESCLN_5_CKMAX_R(x)	((x) << 16)
#define DCU_CTRLDESCLN_5_CKMAX_G(x)	((x) << 8)
#define DCU_CTRLDESCLN_5_CKMAX_B(x)	(x)

#define DCU_CTRLDESCLN_6(x)		(0x214 + (x) * 0x40)
#define DCU_CTRLDESCLN_6_CKMIN_R(x)	((x) << 16)
#define DCU_CTRLDESCLN_6_CKMIN_G(x)	((x) << 8)
#define DCU_CTRLDESCLN_6_CKMIN_B(x)	(x)

#define DCU_CTRLDESCLN_7(x)		(0x218 + (x) * 0x40)
#define DCU_CTRLDESCLN_7_TILE_VER(x)	((x) << 16)
#define DCU_CTRLDESCLN_7_TILE_HOR(x)	(x)

#define DCU_CTRLDESCLN_8(x)		(0x21c + (x) * 0x40)
#define DCU_CTRLDESCLN_8_FG_FCOLOR(x)	(x)

#define DCU_CTRLDESCLN_9(x)		(0x220 + (x) * 0x40)
#define DCU_CTRLDESCLN_9_BG_BCOLOR(x)	(x)

#define DCU_CTRLDESCLN_10(x)		(0x224 + (x) * 0x40)

#ifdef CONFIG_SOC_VF610
#define DCU_TOTAL_LAYER_NUM		64
#define DCU_LAYER_NUM_MAX		6
#else
#define DCU_TOTAL_LAYER_NUM		16
#define DCU_LAYER_NUM_MAX		4
#endif

#define BPP_16_RGB565			4
#define BPP_24_RGB888			5
#define BPP_32_ARGB8888			6

#define TCON_CTRL1			0x00
#define TCON_BYPASS_ENABLE		BIT(29)

#define SCFG_PIXCLKCR			0x28
#define PXCKEN				BIT(31)
#define PXCK_DISABLE			0

#define MFB_SET_ALPHA		_IOW('M', 0, __u8)
#define MFB_GET_ALPHA		_IOR('M', 0, __u8)
#define MFB_SET_LAYER		_IOW('M', 4, struct layer_display_offset)
#define MFB_GET_LAYER		_IOR('M', 4, struct layer_display_offset)

struct dcu_fb_data {
	struct fb_info *fsl_dcu_info[DCU_LAYER_NUM_MAX];
	struct device *dev;
	struct regmap *regmap;
	struct regmap *tcon_regmap;
	struct regmap *scfg_regmap;
	unsigned int irq;
	struct clk *clk;
	struct clk *tcon_clk;
};

struct layer_display_offset {
	int x_layer_d;
	int y_layer_d;
};

struct mfb_info {
	int index;
	char *id;
	unsigned long pseudo_palette[16];
	unsigned char alpha;
	unsigned char blend;
	unsigned int count;
	int x_layer_d;	/* layer display x offset to physical screen */
	int y_layer_d;	/* layer display y offset to physical screen */
	struct dcu_fb_data *parent;
};

enum mfb_index {
	LAYER0 = 0,
	LAYER1,
	LAYER2,
	LAYER3,
	LAYER4,
	LAYER5,
};

static struct mfb_info mfb_template[] = {
	{
		.index = LAYER0,
		.id = "Layer0",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 0,
		.y_layer_d = 0,
	},
	{
		.index = LAYER1,
		.id = "Layer1",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 50,
		.y_layer_d = 50,
	},
	{
		.index = LAYER2,
		.id = "Layer2",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 100,
		.y_layer_d = 100,
	},
	{
		.index = LAYER3,
		.id = "Layer3",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 150,
		.y_layer_d = 150,
	},
	{
		.index = LAYER4,
		.id = "Layer4",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 200,
		.y_layer_d = 200,
	},
	{
		.index = LAYER5,
		.id = "Layer5",
		.alpha = 0xff,
		.blend = 0,
		.count = 0,
		.x_layer_d = 250,
		.y_layer_d = 250,
	},
};

static void reset_total_layers(struct device_node *np,
			       struct dcu_fb_data *dcufb)
{
	int i;

	for (i = 0; i < DCU_TOTAL_LAYER_NUM; i++) {
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_1(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_2(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_3(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_4(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_5(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_6(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_7(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_8(i), 0);
		regmap_write(dcufb->regmap, DCU_CTRLDESCLN_9(i), 0);
		if (of_device_is_compatible(np, "fsl,ls1021a-dcu"))
			regmap_write(dcufb->regmap, DCU_CTRLDESCLN_10(i), 0);
	}

	regmap_write(dcufb->regmap, DCU_UPDATE_MODE, DCU_UPDATE_MODE_READREG);
}

static int enable_panel(struct fb_info *info)
{
	struct fb_var_screeninfo *var = &info->var;
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	unsigned int bpp;

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_1(mfbi->index),
		     DCU_CTRLDESCLN_1_HEIGHT(var->yres) |
		     DCU_CTRLDESCLN_1_WIDTH(var->xres));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_2(mfbi->index),
		     DCU_CTRLDESCLN_2_POSY(mfbi->y_layer_d) |
		     DCU_CTRLDESCLN_2_POSX(mfbi->x_layer_d));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_3(mfbi->index),
		     info->fix.smem_start);

	switch (var->bits_per_pixel) {
	case 16:
		bpp = BPP_16_RGB565;
		break;
	case 24:
		bpp = BPP_24_RGB888;
		break;
	case 32:
		bpp = BPP_32_ARGB8888;
		break;
	default:
		dev_err(dcufb->dev, "unsupported color depth: %u\n",
			var->bits_per_pixel);
		return -EINVAL;
	}

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_4(mfbi->index),
		     DCU_CTRLDESCLN_4_EN |
		     DCU_CTRLDESCLN_4_TRANS(mfbi->alpha) |
		     DCU_CTRLDESCLN_4_BPP(bpp) |
		     DCU_CTRLDESCLN_4_AB(mfbi->blend));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_5(mfbi->index),
		     DCU_CTRLDESCLN_5_CKMAX_R(0xff) |
		     DCU_CTRLDESCLN_5_CKMAX_G(0xff) |
		     DCU_CTRLDESCLN_5_CKMAX_B(0xff));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_6(mfbi->index),
		     DCU_CTRLDESCLN_6_CKMIN_R(0) |
		     DCU_CTRLDESCLN_6_CKMIN_G(0) |
		     DCU_CTRLDESCLN_6_CKMIN_B(0));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_7(mfbi->index),
		     DCU_CTRLDESCLN_7_TILE_VER(0) |
		     DCU_CTRLDESCLN_7_TILE_HOR(0));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_8(mfbi->index),
		     DCU_CTRLDESCLN_8_FG_FCOLOR(0));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_9(mfbi->index),
		     DCU_CTRLDESCLN_9_BG_BCOLOR(0));

	regmap_write(dcufb->regmap, DCU_UPDATE_MODE, DCU_UPDATE_MODE_READREG);

	return 0;
}

static int disable_panel(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_1(mfbi->index),
		     DCU_CTRLDESCLN_1_HEIGHT(0) |
		     DCU_CTRLDESCLN_1_WIDTH(0));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_2(mfbi->index),
		     DCU_CTRLDESCLN_2_POSY(0) |
		     DCU_CTRLDESCLN_2_POSX(0));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_3(mfbi->index), 0);
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_4(mfbi->index), 0);

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_5(mfbi->index),
		     DCU_CTRLDESCLN_5_CKMAX_R(0) |
		     DCU_CTRLDESCLN_5_CKMAX_G(0) |
		     DCU_CTRLDESCLN_5_CKMAX_B(0));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_6(mfbi->index),
		     DCU_CTRLDESCLN_6_CKMIN_R(0) |
		     DCU_CTRLDESCLN_6_CKMIN_G(0) |
		     DCU_CTRLDESCLN_6_CKMIN_B(0));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_7(mfbi->index),
		     DCU_CTRLDESCLN_7_TILE_VER(0) |
		     DCU_CTRLDESCLN_7_TILE_HOR(0));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_8(mfbi->index),
		     DCU_CTRLDESCLN_8_FG_FCOLOR(0));
	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_9(mfbi->index),
		     DCU_CTRLDESCLN_9_BG_BCOLOR(0));

	regmap_write(dcufb->regmap, DCU_UPDATE_MODE,
		     DCU_UPDATE_MODE_READREG);
	return 0;
}

static void enable_controller(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;

	regmap_update_bits(dcufb->regmap, DCU_DCU_MODE,
			   DCU_MODE_DCU_MODE_MASK,
			   DCU_MODE_DCU_MODE(DCU_MODE_NORMAL));
}

static void disable_controller(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;

	regmap_update_bits(dcufb->regmap, DCU_DCU_MODE,
			   DCU_MODE_DCU_MODE_MASK,
			   DCU_MODE_DCU_MODE(DCU_MODE_OFF));
}

static int fsl_dcu_check_var(struct fb_var_screeninfo *var,
		struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;

	if (var->xres_virtual < var->xres)
		var->xres_virtual = var->xres;
	if (var->yres_virtual < var->yres)
		var->yres_virtual = var->yres;

	if (var->xoffset + info->var.xres > info->var.xres_virtual)
		var->xoffset = info->var.xres_virtual - info->var.xres;

	if (var->yoffset + info->var.yres > info->var.yres_virtual)
		var->yoffset = info->var.yres_virtual - info->var.yres;

	switch (var->bits_per_pixel) {
	case 16:
		var->red.length = 5;
		var->red.offset = 11;
		var->red.msb_right = 0;

		var->green.length = 6;
		var->green.offset = 5;
		var->green.msb_right = 0;

		var->blue.length = 5;
		var->blue.offset = 0;
		var->blue.msb_right = 0;

		var->transp.length = 0;
		var->transp.offset = 0;
		var->transp.msb_right = 0;
		break;
	case 24:
		var->red.length = 8;
		var->red.offset = 16;
		var->red.msb_right = 0;

		var->green.length = 8;
		var->green.offset = 8;
		var->green.msb_right = 0;

		var->blue.length = 8;
		var->blue.offset = 0;
		var->blue.msb_right = 0;

		var->transp.length = 0;
		var->transp.offset = 0;
		var->transp.msb_right = 0;
		break;
	case 32:
		var->red.length = 8;
		var->red.offset = 16;
		var->red.msb_right = 0;

		var->green.length = 8;
		var->green.offset = 8;
		var->green.msb_right = 0;

		var->blue.length = 8;
		var->blue.offset = 0;
		var->blue.msb_right = 0;

		var->transp.length = 8;
		var->transp.offset = 24;
		var->transp.msb_right = 0;
		break;
	default:
		dev_err(dcufb->dev, "unsupported color depth: %u\n",
			var->bits_per_pixel);
		return -EINVAL;
	}

	return 0;
}

static int fsl_dcu_calc_div(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	unsigned long long div;

	div = (unsigned long long)(clk_get_rate(dcufb->clk) / 1000);
	div *= info->var.pixclock;
	do_div(div, 1000000000);

	return div;
}

static void update_controller(struct fb_info *info)
{
	struct fb_var_screeninfo *var = &info->var;
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	unsigned int div;

	div = fsl_dcu_calc_div(info);
	regmap_write(dcufb->regmap, DCU_DIV_RATIO, div);

	regmap_write(dcufb->regmap, DCU_DISP_SIZE,
		     DCU_DISP_SIZE_DELTA_Y(var->yres) |
		     DCU_DISP_SIZE_DELTA_X(var->xres / 16));

	/* Horizontal and vertical sync parameters */
	regmap_write(dcufb->regmap, DCU_HSYN_PARA,
		     DCU_HSYN_PARA_BP(var->left_margin) |
		     DCU_HSYN_PARA_PW(var->hsync_len) |
		     DCU_HSYN_PARA_FP(var->right_margin));

	regmap_write(dcufb->regmap, DCU_VSYN_PARA,
		     DCU_VSYN_PARA_BP(var->upper_margin) |
		     DCU_VSYN_PARA_PW(var->vsync_len) |
		     DCU_VSYN_PARA_FP(var->lower_margin));

	regmap_write(dcufb->regmap, DCU_SYN_POL,
		     DCU_SYN_POL_INV_PXCK_FALL | DCU_SYN_POL_NEG_REMAIN |
		     DCU_SYN_POL_INV_VS_LOW | DCU_SYN_POL_INV_HS_LOW);

	regmap_write(dcufb->regmap, DCU_BGND, DCU_BGND_R(0) |
		     DCU_BGND_G(0) | DCU_BGND_B(0));

	regmap_write(dcufb->regmap, DCU_DCU_MODE,
		     DCU_MODE_BLEND_ITER(DCU_LAYER_NUM_MAX) |
		     DCU_MODE_RASTER_EN);

	regmap_write(dcufb->regmap, DCU_THRESHOLD,
		     DCU_THRESHOLD_LS_BF_VS(0x3) |
		     DCU_THRESHOLD_OUT_BUF_HIGH(0x78) |
		     DCU_THRESHOLD_OUT_BUF_LOW(0xa));

	regmap_write(dcufb->regmap, DCU_UPDATE_MODE, DCU_UPDATE_MODE_READREG);
}

static int map_video_memory(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	u32 smem_len = info->fix.line_length * info->var.yres_virtual;
	dma_addr_t smem_start;

	info->fix.smem_len = smem_len;

	info->screen_base = dma_alloc_writecombine(info->device,
		info->fix.smem_len, &smem_start,
		GFP_KERNEL);
	if (!info->screen_base) {
		dev_err(dcufb->dev, "unable to allocate fb memory\n");
		return -ENOMEM;
	}

	info->fix.smem_start = smem_start;
	memset(info->screen_base, 0, info->fix.smem_len);

	return 0;
}

static void unmap_video_memory(struct fb_info *info)
{
	if (!info->screen_base)
		return;

	dma_free_writecombine(info->device, info->fix.smem_len,
		info->screen_base, info->fix.smem_start);

	info->screen_base = NULL;
	info->fix.smem_start = 0;
	info->fix.smem_len = 0;
}

static int fsl_dcu_set_layer(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct fb_var_screeninfo *var = &info->var;
	struct dcu_fb_data *dcufb = mfbi->parent;
	int pixel_offset;
	unsigned long addr;

	pixel_offset = (var->yoffset * var->xres_virtual) + var->xoffset;
	addr = info->fix.smem_start +
		(pixel_offset * (var->bits_per_pixel >> 3));

	regmap_write(dcufb->regmap, DCU_CTRLDESCLN_3(mfbi->index), addr);
	regmap_write(dcufb->regmap, DCU_UPDATE_MODE, DCU_UPDATE_MODE_READREG);

	return 0;
}

static int fsl_dcu_set_par(struct fb_info *info)
{
	unsigned long len;
	struct fb_var_screeninfo *var = &info->var;
	struct fb_fix_screeninfo *fix = &info->fix;
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;

	fix->line_length = var->xres_virtual * var->bits_per_pixel / 8;
	fix->type = FB_TYPE_PACKED_PIXELS;
	fix->accel = FB_ACCEL_NONE;
	fix->visual = FB_VISUAL_TRUECOLOR;
	fix->xpanstep = 1;
	fix->ypanstep = 1;

	len = info->var.yres_virtual * info->fix.line_length;
	if (len != info->fix.smem_len) {
		if (info->fix.smem_start)
			unmap_video_memory(info);

		if (map_video_memory(info)) {
			dev_err(dcufb->dev, "unable to allocate fb memory\n");
			return -ENOMEM;
		}
	}

	/* Only layer 0 could update LCD controller */
	if (mfbi->index == LAYER0) {
		update_controller(info);
		enable_controller(info);
	}

	enable_panel(info);
	return 0;
}

static inline __u32 CNVT_TOHW(__u32 val, __u32 width)
{
	return ((val << width) + 0x7FFF - val) >> 16;
}

static int fsl_dcu_setcolreg(unsigned regno, unsigned red, unsigned green,
			   unsigned blue, unsigned transp, struct fb_info *info)
{
	unsigned int val;
	int ret = -EINVAL;

	/*
	 * If greyscale is true, then we convert the RGB value
	 * to greyscale no matter what visual we are using.
	 */
	if (info->var.grayscale)
		red = green = blue = (19595 * red + 38470 * green +
				      7471 * blue) >> 16;
	switch (info->fix.visual) {
	case FB_VISUAL_TRUECOLOR:
		/*
		 * 16-bit True Colour.  We encode the RGB value
		 * according to the RGB bitfield information.
		 */
		if (regno < 16) {
			u32 *pal = info->pseudo_palette;

			red = CNVT_TOHW(red, info->var.red.length);
			green = CNVT_TOHW(green, info->var.green.length);
			blue = CNVT_TOHW(blue, info->var.blue.length);
			transp = CNVT_TOHW(transp, info->var.transp.length);

			val = (red << info->var.red.offset) |
			    (green << info->var.green.offset) |
			    (blue << info->var.blue.offset) |
			    (transp << info->var.transp.offset);

			pal[regno] = val;
			ret = 0;
		}
		break;
	case FB_VISUAL_STATIC_PSEUDOCOLOR:
	case FB_VISUAL_PSEUDOCOLOR:
		break;
	}

	return ret;
}

static int fsl_dcu_pan_display(struct fb_var_screeninfo *var,
			     struct fb_info *info)
{
	if ((info->var.xoffset == var->xoffset) &&
	    (info->var.yoffset == var->yoffset))
		return 0;

	if ((var->xoffset + info->var.xres) > info->var.xres_virtual
	    || (var->yoffset + info->var.yres) > info->var.yres_virtual)
		return -EINVAL;

	info->var.xoffset = var->xoffset;
	info->var.yoffset = var->yoffset;

	if (var->vmode & FB_VMODE_YWRAP)
		info->var.vmode |= FB_VMODE_YWRAP;
	else
		info->var.vmode &= ~FB_VMODE_YWRAP;

	fsl_dcu_set_layer(info);

	return 0;
}

static int fsl_dcu_blank(int blank_mode, struct fb_info *info)
{
	switch (blank_mode) {
	case FB_BLANK_VSYNC_SUSPEND:
	case FB_BLANK_HSYNC_SUSPEND:
	case FB_BLANK_NORMAL:
		disable_panel(info);
		break;
	case FB_BLANK_POWERDOWN:
		disable_controller(info);
		break;
	case FB_BLANK_UNBLANK:
		enable_panel(info);
		break;
	}

	return 0;
}

static int fsl_dcu_ioctl(struct fb_info *info, unsigned int cmd,
		unsigned long arg)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	struct layer_display_offset layer_d;
	void __user *buf = (void __user *)arg;
	unsigned char alpha;

	switch (cmd) {
	case MFB_SET_LAYER:
		if (copy_from_user(&layer_d, buf, sizeof(layer_d)))
			return -EFAULT;
		mfbi->x_layer_d = layer_d.x_layer_d;
		mfbi->y_layer_d = layer_d.y_layer_d;
		fsl_dcu_set_par(info);
		break;
	case MFB_GET_LAYER:
		layer_d.x_layer_d = mfbi->x_layer_d;
		layer_d.y_layer_d = mfbi->y_layer_d;
		if (copy_to_user(buf, &layer_d, sizeof(layer_d)))
			return -EFAULT;
		break;
	case MFB_GET_ALPHA:
		alpha = mfbi->alpha;
		if (copy_to_user(buf, &alpha, sizeof(alpha)))
			return -EFAULT;
		break;
	case MFB_SET_ALPHA:
		if (copy_from_user(&alpha, buf, sizeof(alpha)))
			return -EFAULT;
		mfbi->blend = 1;
		mfbi->alpha = alpha;
		fsl_dcu_set_par(info);
		break;
	default:
		dev_err(dcufb->dev, "unknown ioctl command (0x%08X)\n", cmd);
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int fsl_dcu_open(struct fb_info *info, int user)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	int ret = 0;

	mfbi->index = info->node;

	mfbi->count++;
	if (mfbi->count == 1) {
		fsl_dcu_check_var(&info->var, info);
		ret = fsl_dcu_set_par(info);
		if (ret < 0)
			mfbi->count--;
		else
			regmap_update_bits(dcufb->regmap, DCU_INT_MASK,
					   DCU_INT_MASK_ALL, DCU_INT_MASK_ALL);
	}

	return ret;
}

static int fsl_dcu_release(struct fb_info *info, int user)
{
	struct mfb_info *mfbi = info->par;
	int ret = 0;

	mfbi->count--;
	if (mfbi->count == 0)
		ret = disable_panel(info);

	return ret;
}

static struct fb_ops fsl_dcu_ops = {
	.owner = THIS_MODULE,
	.fb_check_var = fsl_dcu_check_var,
	.fb_set_par = fsl_dcu_set_par,
	.fb_setcolreg = fsl_dcu_setcolreg,
	.fb_blank = fsl_dcu_blank,
	.fb_pan_display = fsl_dcu_pan_display,
	.fb_fillrect = cfb_fillrect,
	.fb_copyarea = cfb_copyarea,
	.fb_imageblit = cfb_imageblit,
	.fb_ioctl = fsl_dcu_ioctl,
	.fb_open = fsl_dcu_open,
	.fb_release = fsl_dcu_release,
};

static int fsl_dcu_init_fbinfo(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct fb_var_screeninfo *var = &info->var;
	struct dcu_fb_data *dcufb = mfbi->parent;
	struct device_node *np = dcufb->dev->of_node;
	struct device_node *display_np;
	struct device_node *timings_np;
	struct display_timings *timings;
	int i;
	int ret = 0;

	display_np = of_parse_phandle(np, "display", 0);
	if (!display_np) {
		dev_err(dcufb->dev, "failed to find display phandle\n");
		return -ENOENT;
	}

	ret = of_property_read_u32(display_np, "bits-per-pixel",
				   &var->bits_per_pixel);
	if (ret < 0) {
		dev_err(dcufb->dev, "failed to get property bits-per-pixel\n");
		goto put_display_node;
	}

	timings = of_get_display_timings(display_np);
	if (!timings) {
		dev_err(dcufb->dev, "failed to get display timings\n");
		ret = -ENOENT;
		goto put_display_node;
	}

	timings_np = of_find_node_by_name(display_np,
					  "display-timings");
	if (!timings_np) {
		dev_err(dcufb->dev, "failed to find display-timings node\n");
		ret = -ENOENT;
		goto put_display_node;
	}

	for (i = 0; i < of_get_child_count(timings_np); i++) {
		struct videomode vm;
		struct fb_videomode fb_vm;

		ret = videomode_from_timings(timings, &vm, i);
		if (ret < 0)
			goto put_timings_node;

		ret = fb_videomode_from_videomode(&vm, &fb_vm);
		if (ret < 0)
			goto put_timings_node;

		fb_add_videomode(&fb_vm, &info->modelist);
	}

	return 0;
put_timings_node:
	of_node_put(timings_np);
put_display_node:
	of_node_put(display_np);
	return ret;
}

static int install_framebuffer(struct fb_info *info)
{
	struct mfb_info *mfbi = info->par;
	struct dcu_fb_data *dcufb = mfbi->parent;
	struct fb_modelist *modelist;
	int ret;

	info->var.activate = FB_ACTIVATE_NOW;
	info->fbops = &fsl_dcu_ops;
	info->flags = FBINFO_FLAG_DEFAULT;
	info->pseudo_palette = &mfbi->pseudo_palette;

	fb_alloc_cmap(&info->cmap, 16, 0);

	INIT_LIST_HEAD(&info->modelist);

	ret = fsl_dcu_init_fbinfo(info);
	if (ret)
		return ret;

	modelist = list_first_entry(&info->modelist,
			struct fb_modelist, list);
	fb_videomode_to_var(&info->var, &modelist->mode);

	fsl_dcu_check_var(&info->var, info);
	ret = register_framebuffer(info);
	if (ret < 0) {
		dev_err(dcufb->dev, "failed to register framebuffer device\n");
		return ret;
	}

	pr_info("fb%d: fb device registered successfully.\n", info->node);
	return 0;
}

static void uninstall_framebuffer(struct fb_info *info)
{
	unregister_framebuffer(info);
	unmap_video_memory(info);

	if (&info->cmap)
		fb_dealloc_cmap(&info->cmap);
}

static irqreturn_t fsl_dcu_irq(int irq, void *dev_id)
{
	struct dcu_fb_data *dcufb = dev_id;
	unsigned int status;

	regmap_read(dcufb->regmap, DCU_INT_STATUS, &status);

	if (status & DCU_INT_STATUS_UNDRUN) {
		regmap_update_bits(dcufb->regmap, DCU_DCU_MODE,
				   DCU_MODE_DCU_MODE_MASK,
				   DCU_MODE_DCU_MODE(DCU_MODE_OFF));
		udelay(1);
		regmap_update_bits(dcufb->regmap, DCU_DCU_MODE,
				   DCU_MODE_DCU_MODE_MASK,
				   DCU_MODE_DCU_MODE(DCU_MODE_NORMAL));
	}

	regmap_write(dcufb->regmap, DCU_INT_STATUS, status);

	return IRQ_HANDLED;
}

static const struct regmap_config fsl_tcon_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,

	.max_register = TCON_CTRL1,
	.cache_type = REGCACHE_FLAT,
};

static int bypass_tcon(struct dcu_fb_data *dcufb, struct device_node *np)
{
	struct device_node *tcon_np;
	struct platform_device *pdev;
	struct resource *res;
	void __iomem *base;

	tcon_np = of_parse_phandle(np, "tcon-controller", 0);
	if (!tcon_np)
		return 0;

	pdev = of_find_device_by_node(tcon_np);
	if (!pdev)
		return -EINVAL;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base)) {
		dev_err(&pdev->dev, "could not ioremap resource\n");
		return PTR_ERR(base);
	}

	dcufb->tcon_clk = devm_clk_get(&pdev->dev, "tcon");
	if (IS_ERR(dcufb->tcon_clk))
		return PTR_ERR(dcufb->tcon_clk);
	clk_prepare_enable(dcufb->tcon_clk);

	dcufb->tcon_regmap = devm_regmap_init_mmio_clk(&pdev->dev,
			"tcon", base, &fsl_tcon_regmap_config);
	if (IS_ERR(dcufb->tcon_regmap)) {
		dev_err(&pdev->dev, "regmap init failed\n");
		return PTR_ERR(dcufb->tcon_regmap);
	}

	regmap_write(dcufb->tcon_regmap, TCON_CTRL1, TCON_BYPASS_ENABLE);

	return 0;
}

static const struct regmap_config fsl_scfg_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,

	.max_register = 0x28,
	.cache_type = REGCACHE_FLAT,
};

static int scfg_config(struct dcu_fb_data *dcufb, struct device_node *np)
{
	struct device_node *scfg_np;
	struct platform_device *pdev;
	struct resource *res;
	void __iomem *base;

	scfg_np = of_parse_phandle(np, "scfg-controller", 0);
	if (!scfg_np)
		return 0;

	pdev = of_find_device_by_node(scfg_np);
	if (!pdev)
		return -EINVAL;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res)
		return -ENODEV;

	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base)) {
		dev_err(&pdev->dev, "could not ioremap resource\n");
		return PTR_ERR(base);
	}

	dcufb->scfg_regmap = devm_regmap_init_mmio_clk(&pdev->dev,
			NULL, base, &fsl_scfg_regmap_config);
	if (IS_ERR(dcufb->scfg_regmap)) {
		dev_err(&pdev->dev, "regmap init failed\n");
		return PTR_ERR(dcufb->scfg_regmap);
	}

	regmap_write(dcufb->scfg_regmap, 0x028, 0x80000000);

	return 0;
}

static const struct regmap_config fsl_dcu_regmap_config = {
	.reg_bits = 32,
	.reg_stride = 4,
	.val_bits = 32,

	.max_register = 0x5e8,
	.cache_type = REGCACHE_RBTREE,
};

static int fsl_dcu_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct dcu_fb_data *dcufb;
	struct mfb_info *mfbi;
	struct resource *res;
	void __iomem *base;
	int ret = 0;
	int i;

	dcufb = devm_kzalloc(&pdev->dev,
		sizeof(struct dcu_fb_data), GFP_KERNEL);
	if (!dcufb)
		return -ENOMEM;

	dcufb->dev = &pdev->dev;
	dev_set_drvdata(&pdev->dev, dcufb);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "could not get memory IO resource\n");
		return -ENODEV;
	}

	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base)) {
		dev_err(&pdev->dev, "could not ioremap resource\n");
		return PTR_ERR(base);
	}

	dcufb->regmap = devm_regmap_init_mmio_clk(&pdev->dev,
				NULL, base, &fsl_dcu_regmap_config);
	if (IS_ERR(dcufb->regmap)) {
		dev_err(&pdev->dev, "regmap init failed\n");
		return PTR_ERR(dcufb->regmap);
	}

	dcufb->irq = platform_get_irq(pdev, 0);
	if (!dcufb->irq) {
		dev_err(&pdev->dev, "could not get irq\n");
		return -EINVAL;
	}

	ret = devm_request_irq(&pdev->dev, dcufb->irq, fsl_dcu_irq,
			0, DRIVER_NAME, dcufb);
	if (ret) {
		dev_err(&pdev->dev, "could not request irq\n");
		return -EINVAL;
	}

	/* Put TCON in bypass mode, so the input signals from DCU are passed
	 * through TCON unchanged */
	ret = bypass_tcon(dcufb, np);
	if (ret) {
		dev_err(&pdev->dev, "could not bypass TCON\n");
		return -EINVAL;
	}

	ret = scfg_config(dcufb, np);
	if (ret) {
		dev_err(&pdev->dev, "could not config scfg\n");
		return -EINVAL;
	}

	dcufb->clk = devm_clk_get(&pdev->dev, "dcu");
	if (IS_ERR(dcufb->clk)) {
		ret = PTR_ERR(dcufb->clk);
		dev_err(&pdev->dev, "could not get clock\n");
		return -EINVAL;
	}
	clk_prepare_enable(dcufb->clk);

	pm_runtime_enable(dcufb->dev);
	pm_runtime_get_sync(dcufb->dev);

	reset_total_layers(np, dcufb);

	for (i = 0; i < ARRAY_SIZE(dcufb->fsl_dcu_info); i++) {
		dcufb->fsl_dcu_info[i] =
			framebuffer_alloc(sizeof(struct mfb_info), &pdev->dev);
		if (!dcufb->fsl_dcu_info[i]) {
			ret = -ENOMEM;
			goto err;
		}

		dcufb->fsl_dcu_info[i]->fix.smem_start = 0;

		mfbi = dcufb->fsl_dcu_info[i]->par;
		memcpy(mfbi, &mfb_template[i], sizeof(struct mfb_info));
		mfbi->parent = dcufb;

		ret = install_framebuffer(dcufb->fsl_dcu_info[i]);
		if (ret) {
			dev_err(&pdev->dev,
				"could not register framebuffer %d\n", i);
			goto err;
		}
	}

	goto out;
err:
	for (i = 0; i < ARRAY_SIZE(dcufb->fsl_dcu_info); i++) {
		if (dcufb->fsl_dcu_info[i])
			framebuffer_release(dcufb->fsl_dcu_info[i]);
	}

	clk_disable_unprepare(dcufb->clk);
out:
	pm_runtime_put_sync(dcufb->dev);
	pm_runtime_disable(dcufb->dev);
	return ret;
}

static int fsl_dcu_remove(struct platform_device *pdev)
{
	struct dcu_fb_data *dcufb = dev_get_drvdata(&pdev->dev);
	int i;

	pm_runtime_get_sync(dcufb->dev);

	disable_controller(dcufb->fsl_dcu_info[0]);

	clk_disable_unprepare(dcufb->tcon_clk);
	clk_disable_unprepare(dcufb->clk);
	free_irq(dcufb->irq, dcufb);

	for (i = 0; i < ARRAY_SIZE(dcufb->fsl_dcu_info); i++) {
		uninstall_framebuffer(dcufb->fsl_dcu_info[i]);
		framebuffer_release(dcufb->fsl_dcu_info[i]);
	}

	pm_runtime_put_sync(dcufb->dev);
	pm_runtime_disable(dcufb->dev);

	return 0;
}

#ifdef CONFIG_PM_RUNTIME
static int fsl_dcu_runtime_suspend(struct device *dev)
{
	struct dcu_fb_data *dcufb = dev_get_drvdata(dev);

	clk_disable_unprepare(dcufb->clk);
	clk_disable_unprepare(dcufb->tcon_clk);

	return 0;
}

static int fsl_dcu_runtime_resume(struct device *dev)
{
	struct dcu_fb_data *dcufb = dev_get_drvdata(dev);

	clk_prepare_enable(dcufb->tcon_clk);
	clk_prepare_enable(dcufb->clk);

	return 0;
}
#endif

#ifdef CONFIG_PM_SLEEP
static int fsl_dcu_suspend(struct device *dev)
{
	struct dcu_fb_data *dcufb = dev_get_drvdata(dev);

	regmap_write(dcufb->scfg_regmap, SCFG_PIXCLKCR, PXCK_DISABLE);
	regcache_cache_only(dcufb->regmap, true);
	regcache_mark_dirty(dcufb->regmap);
	clk_disable_unprepare(dcufb->clk);

	if (dcufb->tcon_regmap) {
		regcache_cache_only(dcufb->tcon_regmap, true);
		regcache_mark_dirty(dcufb->tcon_regmap);
		clk_disable_unprepare(dcufb->tcon_clk);
	}

	if (dcufb->scfg_regmap) {
		regcache_cache_only(dcufb->scfg_regmap, true);
		regcache_mark_dirty(dcufb->scfg_regmap);
	}

	return 0;
}

static int fsl_dcu_resume(struct device *dev)
{
	struct dcu_fb_data *dcufb = dev_get_drvdata(dev);
	struct device_node *np = dev->of_node;

	/* Enable clocks and restore all registers */
	if (dcufb->tcon_regmap) {
		clk_prepare_enable(dcufb->tcon_clk);
		regcache_cache_only(dcufb->tcon_regmap, false);
		regcache_sync(dcufb->tcon_regmap);
	}

	if (dcufb->scfg_regmap) {
		regcache_cache_only(dcufb->scfg_regmap, false);
		regcache_sync(dcufb->scfg_regmap);
	}

	clk_prepare_enable(dcufb->clk);
	reset_total_layers(np, dcufb);
	regcache_cache_only(dcufb->regmap, false);
	regcache_sync(dcufb->regmap);
	regmap_write(dcufb->scfg_regmap, SCFG_PIXCLKCR, PXCKEN);

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static const struct dev_pm_ops fsl_dcu_pm_ops = {
#ifdef CONFIG_PM_RUNTIME
	SET_RUNTIME_PM_OPS(fsl_dcu_runtime_suspend,
			   fsl_dcu_runtime_resume, NULL)
#endif
#ifdef CONFIG_PM_SLEEP
	SET_SYSTEM_SLEEP_PM_OPS(fsl_dcu_suspend, fsl_dcu_resume)
#endif
};

static const struct of_device_id fsl_dcu_dt_ids[] = {
	{ .compatible = "fsl,vf610-dcu", },
	{ .compatible = "fsl,ls1021a-dcu", },
	{}
};

static struct platform_driver fsl_dcu_driver = {
	.driver = {
		.name = DRIVER_NAME,
		.owner = THIS_MODULE,
		.of_match_table = fsl_dcu_dt_ids,
		.pm = &fsl_dcu_pm_ops,
	},
	.probe = fsl_dcu_probe,
	.remove = fsl_dcu_remove,
};

module_platform_driver(fsl_dcu_driver);

MODULE_AUTHOR("Alison Wang");
MODULE_DESCRIPTION("Freescale DCU framebuffer driver");
MODULE_LICENSE("GPL v2");
