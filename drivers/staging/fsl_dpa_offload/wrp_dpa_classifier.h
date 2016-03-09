
/* Copyright 2008-2012 Freescale Semiconductor, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Internal DPA Classifier Wrapper Application Programming Interface
 */

#ifndef __WRP_DPA_CLASSIFIER_H
#define __WRP_DPA_CLASSIFIER_H


/* Other includes */
#include "linux/fs.h"


#define WRP_DPA_CLS_CDEVNAME				"dpa_classifier"
#define WRP_DPA_CLS_CLASS_NAME				"dpa_classifier"


int	wrp_dpa_classif_init(void);

int	wrp_dpa_classif_exit(void);

int	wrp_dpa_classif_open(struct inode *inode, struct file *filp);

int	wrp_dpa_classif_release(struct inode *inode, struct file *filp);

ssize_t	wrp_dpa_classif_read(
			struct file	*filp,
			char __user	*buf,
			size_t		len,
			loff_t		*offp);

ssize_t	wrp_dpa_classif_write(
			struct file		*filp,
			const char __user	*buf,
			size_t			len,
			loff_t			*offp);

long	wrp_dpa_classif_ioctl(
			struct file	*filp,
			unsigned int	cmd,
			unsigned long	args);

long	wrp_dpa_classif_do_ioctl(
			struct file	*filp,
			unsigned int	cmd,
			unsigned long	args,
			bool		compat_mode);

#ifdef CONFIG_COMPAT
long	wrp_dpa_classif_compat_ioctl(
			struct file	*filp,
			unsigned int	cmd,
			unsigned long	args);
#endif

#endif /* __WRP_DPA_CLASSIFIER_H */
