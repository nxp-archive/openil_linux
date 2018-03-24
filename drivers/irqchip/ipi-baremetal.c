/*
 * IPI for inter-core communiction for NXP Layerscape baremetal
 *
 * Copyright 2018 NXP
 *
 * Author: Liu Gang <gang.liu@nxp.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of the above-listed copyright holders nor the
 *	 names of any contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <asm/siginfo.h>
#include <linux/uaccess.h>

#define DEVICE_NAME	"ipi_bm"

/*
 * choose 50 as baremetal signal number.
 * real-time signals are in the range of 33 to 64.
 */
#define SIG_BM 50

int pid;

int ipi_baremetal_open(struct inode *inode, struct file *filp)
{
	pr_info("ipi_bm device open!\n");
	return 0;
}

ssize_t ipi_baremetal_read(struct file *file,
	char __user *buff, size_t count, loff_t *offp)
{
	pr_info("ipi_bm device read!\n");
	return 0;
}

ssize_t ipi_baremetal_write(struct file *file,
	const char __user *buff, size_t count, loff_t *offp)
{
	char mybuf[10];
	int ret;

	/* read the value from user space */
	if (count > 10)
		return -EINVAL;
	copy_from_user(mybuf, buff, count);
	ret = sscanf(mybuf, "%d", &pid);
	if (ret < 0)
		return -EINVAL;
	pr_info("ipi_bm device write. pid = %d\n", pid);

	return 0;
}

static int ipi_baremetal_release(struct inode *inode, struct file *file)
{
	pr_info("ipi_bm device close!\n");
	return 0;
}

int ipi_baremetal_handle(u32 irqnr, u32 irqsrc)
{
	struct siginfo info;
	struct task_struct *t;
	int si_data;
	int ret;

	if (!pid)
		return 0;

	si_data = (irqnr << 16) | irqsrc;
	/* send the signal */
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = SIG_BM;
	info.si_code = SI_QUEUE;
	info.si_int = si_data;

	rcu_read_lock();
	/* find the task_struct associated with this pid */
	t = find_task_by_vpid(pid);
	if (t == NULL) {
		pr_info("no such pid\n");
		rcu_read_unlock();
		return -ENODEV;
	}
	rcu_read_unlock();

	/* send the signal */
	ret = send_sig_info(SIG_BM, &info, t);
	if (ret < 0) {
		pr_info("error sending signal\n");
		return ret;
	}
	return 0;
}

const struct file_operations ipi_bm_ops = {
	.owner = THIS_MODULE,
	.open = ipi_baremetal_open,
	.release = ipi_baremetal_release,
	.read = ipi_baremetal_read,
	.write = ipi_baremetal_write,
};

static struct miscdevice ipi_bm_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = DEVICE_NAME,
	.fops = &ipi_bm_ops,
};

static int __init ipi_baremetal_init(void)
{
	int ret;

	pr_info("NXP inter-core communiction IRQ driver\n");
	ret = misc_register(&ipi_bm_misc);
	if (ret < 0) {
		pr_info("Register ipi_bm error! ret: %d\n", ret);
		return ret;
	}
	pr_info("ipi_bm device created!\n");
	return 0;
}

static void __exit ipi_baremetal_exit(void)
{
	pid = 0;
	misc_deregister(&ipi_bm_misc);
	pr_info("ipi_bm device deleted!\n");
}

module_init(ipi_baremetal_init);
module_exit(ipi_baremetal_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NXP");
MODULE_DESCRIPTION("NXP inter-core communiction IPI driver");
