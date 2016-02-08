/* Copyright 2013-2015 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * * Neither the name of the above-listed copyright holders nor the
 * names of any contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
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
#include "../../fsl-mc/include/mc-sys.h"
#include "../../fsl-mc/include/mc-cmd.h"
#include "dpdcei.h"
#include "dpdcei-cmd.h"

int dpdcei_open(struct fsl_mc_io *mc_io, int dpdcei_id, uint16_t *token)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_OPEN,
					  MC_CMD_PRI_LOW,
					  0);
	DPDCEI_CMD_OPEN(cmd, dpdcei_id);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*token = MC_CMD_HDR_READ_TOKEN(cmd.header);

	return 0;
}

int dpdcei_close(struct fsl_mc_io *mc_io, uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_CLOSE,
					  MC_CMD_PRI_HIGH, token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_create(struct fsl_mc_io *mc_io,
		  const struct dpdcei_cfg *cfg,
		  uint16_t *token)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_CREATE,
					  MC_CMD_PRI_LOW,
					  0);
	DPDCEI_CMD_CREATE(cmd, cfg);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*token = MC_CMD_HDR_READ_TOKEN(cmd.header);

	return 0;
}

int dpdcei_destroy(struct fsl_mc_io *mc_io, uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_DESTROY,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}


int dpdcei_enable(struct fsl_mc_io *mc_io, uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_ENABLE,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_disable(struct fsl_mc_io *mc_io, uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_DISABLE,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_is_enabled(struct fsl_mc_io *mc_io, uint16_t token, int *en)
{
	struct mc_command cmd = { 0 };
	int err;
	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_IS_ENABLED,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_IS_ENABLED(cmd, *en);

	return 0;
}

int dpdcei_reset(struct fsl_mc_io *mc_io, uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_RESET,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_irq(struct fsl_mc_io *mc_io,
		   uint16_t token,
		   uint8_t irq_index,
		   int *type,
		   uint64_t *irq_addr,
		   u32 *irq_val,
		   int *user_irq_id)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_IRQ,
					  MC_CMD_PRI_LOW,
					  token);
	DPDCEI_CMD_GET_IRQ(cmd, irq_index);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_IRQ(cmd, *type, *irq_addr, *irq_val, *user_irq_id);

	return 0;
}

int dpdcei_set_irq(struct fsl_mc_io *mc_io,
		   uint16_t token,
		   uint8_t irq_index,
		   uint64_t irq_addr,
		   u32 irq_val,
		   int user_irq_id)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_SET_IRQ,
					  MC_CMD_PRI_LOW,
					  token);
	DPDCEI_CMD_SET_IRQ(cmd, irq_index, irq_addr, irq_val, user_irq_id);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_irq_enable(struct fsl_mc_io *mc_io,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t *en)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_IRQ_ENABLE,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_GET_IRQ_ENABLE(cmd, irq_index);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_IRQ_ENABLE(cmd, *en);

	return 0;
}

int dpdcei_set_irq_enable(struct fsl_mc_io *mc_io,
			  uint16_t token,
			  uint8_t irq_index,
			  uint8_t en)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_SET_IRQ_ENABLE,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_SET_IRQ_ENABLE(cmd, irq_index, en);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_irq_mask(struct fsl_mc_io *mc_io,
			uint16_t token,
			uint8_t irq_index,
			u32 *mask)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_IRQ_MASK,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_GET_IRQ_MASK(cmd, irq_index);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_IRQ_MASK(cmd, *mask);

	return 0;
}

int dpdcei_set_irq_mask(struct fsl_mc_io *mc_io,
			uint16_t token,
			uint8_t irq_index,
			u32 mask)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_SET_IRQ_MASK,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_SET_IRQ_MASK(cmd, irq_index, mask);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_irq_status(struct fsl_mc_io *mc_io,
			  uint16_t token,
			  uint8_t irq_index,
			  u32 *status)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_IRQ_STATUS,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_GET_IRQ_STATUS(cmd, irq_index);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_IRQ_STATUS(cmd, *status);

	return 0;
}

int dpdcei_clear_irq_status(struct fsl_mc_io *mc_io,
			    uint16_t token,
			    uint8_t irq_index,
			    u32 status)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_CLEAR_IRQ_STATUS,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_CLEAR_IRQ_STATUS(cmd, irq_index, status);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_attributes(struct fsl_mc_io *mc_io,
			  uint16_t token,
			  struct dpdcei_attr *attr)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_ATTR,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_ATTR(cmd, attr);

	return 0;
}

int dpdcei_set_rx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			const struct dpdcei_rx_queue_cfg *cfg)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_SET_RX_QUEUE,
					  MC_CMD_PRI_LOW, token);
	DPDCEI_CMD_SET_RX_QUEUE(cmd, cfg);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

int dpdcei_get_rx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			struct dpdcei_rx_queue_attr *attr)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_RX_QUEUE,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_RX_QUEUE(cmd, attr);

	return 0;
}

int dpdcei_get_tx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			struct dpdcei_tx_queue_attr *attr)
{
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPDCEI_CMDID_GET_TX_QUEUE,
					  MC_CMD_PRI_LOW,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	DPDCEI_RSP_GET_TX_QUEUE(cmd, attr);

	return 0;
}
