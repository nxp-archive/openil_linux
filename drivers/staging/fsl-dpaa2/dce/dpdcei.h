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
#ifndef __FSL_DPDCEI_H
#define __FSL_DPDCEI_H

/* Data Path DCE Interface API
 * Contains initialization APIs and runtime control APIs for DPDCEI
 */

struct fsl_mc_io;

/* General DPDCEI macros */

#define DPDCEI_MAX_IRQ_NUM		0 /* TODO */

/* Indicates an invalid frame queue */
#define DPDCEI_FQID_NOT_VALID	(u32)(-1)

/**
 * enum dpdcei_ngine - DCE engine block
 * @DPDCEI_ENGINE_COMPRESSION: Engine compression
 * @DPDCEI_ENGINE_DECOMPRESSION: Engine decompression
 */
enum dpdcei_engine {
	DPDCEI_ENGINE_COMPRESSION,
	DPDCEI_ENGINE_DECOMPRESSION
};

/**
 * dpdcei_open() - Open a control session for the specified object
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @dpdcei_id: DPDCEI unique ID
 *
 * This function can be used to open a control session for an
 * already created object; an object may have been declared in
 * the DPL or by calling the dpdcei_create() function.
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent commands for
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_open(struct fsl_mc_io *mc_io, int dpdcei_id, uint16_t *token);

/**
 * dpdcei_close() - Close the control session of the object
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 *
 * After this function is called, no further operations are
 * allowed on the object without opening a new control session.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_close(struct fsl_mc_io *mc_io, uint16_t token);

/**
 * struct dpdcei_cfg - Structure representing DPDCEI configuration
 * @engine: compression or decompression engine to be selected
 * @priority: Priority for the DCE hardware processing (valid values 1-8).
 */
struct dpdcei_cfg {
	enum dpdcei_engine engine;
	uint8_t priority;
};

/**
 * dpdcei_create() - Create the DPDCEI object
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @cfg: configuration parameters
 *
 * Create the DPDCEI object, allocate required resources and
 * perform required initialization.
 *
 * The object can be created either by declaring it in the
 * DPL file, or by calling this function.
 *
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent calls to
 * this specific object. For objects that are created using the
 * DPL file, call dpdcei_open() function to get an authentication
 * token first.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_create(struct fsl_mc_io *mc_io,
		  const struct dpdcei_cfg *cfg,
		  uint16_t *token);

/**
 * dpdcei_destroy() - Destroy the DPDCEI object and release all its resources.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 *
 * Return:	'0' on Success; error code otherwise.
 */
int dpdcei_destroy(struct fsl_mc_io *mc_io, uint16_t token);

/**
 * dpdcei_enable() - Enable the DPDCEI, allow sending and receiving frames.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_enable(struct fsl_mc_io *mc_io, uint16_t token);

/**
 * dpdcei_disable() - Disable the DPDCEI, stop sending and receiving frames.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_disable(struct fsl_mc_io *mc_io, uint16_t token);

/**
 * dpdcei_is_enabled() - Check if the DPDCEI is enabled.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @en:	Return '1' for object enabled/'0' otherwise
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_is_enabled(struct fsl_mc_io *mc_io, uint16_t token, int *en);

/**
 * dpdcei_reset() - Reset the DPDCEI, returns the object to initial state.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_reset(struct fsl_mc_io *mc_io, uint16_t token);

/**
 * dpdcei_set_irq() - Set IRQ information for the DPDCEI to trigger an interrupt
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPDCEI object
 * @irq_index:	Identifies the interrupt index to configure
 * @irq_addr:	Address that must be written to
 *				signal a message-based interrupt
 * @irq_val:	Value to write into irq_addr address
 * @user_irq_id: A user defined number associated with this IRQ
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_irq(struct fsl_mc_io *mc_io,
		   uint16_t token,
		 uint8_t irq_index,
		 uint64_t irq_addr,
		 u32 irq_val,
		 int user_irq_id);

/**
 * @dpdcei_get_irq() - Get IRQ information from the DPDCEI
 *
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @type:		Returned interrupt type: 0 represents message interrupt
 *				type (both irq_addr and irq_val are valid)
 * @irq_addr:	Returned address that must be written to
 *				signal the message-based interrupt
 * @irq_val:	Value to write into irq_addr address
 * @user_irq_id: A user defined number associated with this IRQ
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq(struct fsl_mc_io *mc_io,
		   uint16_t token,
		 uint8_t irq_index,
		 int *type,
		 uint64_t *irq_addr,
		 u32 *irq_val,
		 int *user_irq_id);

/**
 * dpdcei_set_irq_enable() - Set overall interrupt state.
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPCI object
 * @irq_index:	The interrupt index to configure
 * @en:			Interrupt state - enable = 1, disable = 0
 *
 * Allows GPP software to control when interrupts are generated.
 * Each interrupt can have up to 32 causes.  The enable/disable control's the
 * overall interrupt state. if the interrupt is disabled no causes will cause
 * an interrupt
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_irq_enable(struct fsl_mc_io *mc_io,
			  uint16_t token,
			uint8_t irq_index,
			uint8_t en);

/**
 * dpdcei_get_irq_enable() - Get overall interrupt state
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @en:			Returned Interrupt state - enable = 1, disable = 0
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_enable(struct fsl_mc_io *mc_io,
			  uint16_t token,
			uint8_t irq_index,
			uint8_t *en);

/**
 * dpdcei_set_irq_mask() - Set interrupt mask.
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPCI object
 * @irq_index:	The interrupt index to configure
 * @mask:		event mask to trigger interrupt;
 *				each bit:
 *					0 = ignore event
 *					1 = consider event for asserting irq
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_irq_mask(struct fsl_mc_io *mc_io,
			uint16_t token,
		      uint8_t irq_index,
		      u32 mask);

/**
 * dpdcei_get_irq_mask() - Get interrupt mask.
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @mask:		Returned event mask to trigger interrupt
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_mask(struct fsl_mc_io *mc_io,
			uint16_t token,
		      uint8_t irq_index,
		      u32 *mask);

/**
 * dpdcei_get_irq_status() - Get the current status of any pending interrupts
 * @mc_io:		Pointer to MC portal's I/O object
 * @token:		Token of DPDCEI object
 * @irq_index:	The interrupt index to configure
 * @status:		Returned interrupts status - one bit per cause:
 *					0 = no interrupt pending
 *					1 = interrupt pending
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_irq_status(struct fsl_mc_io *mc_io,
			  uint16_t token,
			uint8_t irq_index,
			u32 *status);

/**
 * dpdcei_clear_irq_status() - Clear a pending interrupt's status
 * @mc_io		Pointer to MC portal's I/O object
 * @token		Token of DPDCEI object
 * @irq_index	The interrupt index to configure
 * @status		bits to clear (W1C) - one bit per cause:
 *					0 = don't change
 *					1 = clear status bit
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_clear_irq_status(struct fsl_mc_io *mc_io,
			    uint16_t token,
			  uint8_t irq_index,
			  u32 status);
/**
 * struct dpdcei_attr - Structure representing DPDCEI attributes
 * @id: DPDCEI object ID
 * @engine: DCE engine block
 * @version: DPDCEI version
 */
struct dpdcei_attr {
	int id;
	enum dpdcei_engine engine;
	/**
	 * struct version - DPDCEI version
	 * @major: DPDCEI major version
	 * @minor: DPDCEI minor version
	 */
	struct {
		uint16_t major;
		uint16_t minor;
	} version;
};

/**
 * dpdcei_get_attributes() - Retrieve DPDCEI attributes.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @attr: Returned  object's attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_attributes(struct fsl_mc_io *mc_io,
			  uint16_t token,
			  struct dpdcei_attr *attr);

/**
 * enum dpdcei_dest - DPDCEI destination types
 * @DPDCEI_DEST_NONE:  Unassigned destination; The queue is set in parked mode
 *			and does not generate FQDAN notifications;
 *			user is expected to dequeue from the queue based on
 *			polling or other user-defined method
 * @DPDCEI_DEST_DPIO: The queue is set in schedule mode and generates FQDAN
 *			notifications to the specified DPIO; user is expected to
 *			dequeue from the queue only after notification is
 *			received
 * @DPDCEI_DEST_DPCON: The queue is set in schedule mode and does not generate
 *			FQDAN notifications, but is connected to the specified
 *			DPCON object;
 *			user is expected to dequeue from the DPCON channel
 */
enum dpdcei_dest {
	DPDCEI_DEST_NONE = 0,
	DPDCEI_DEST_DPIO = 1,
	DPDCEI_DEST_DPCON = 2
};

/**
 * struct dpdcei_dest_cfg - Structure representing DPDCEI destination parameters
 * @dest_type: Destination type
 * @dest_id: Either DPIO ID or DPCON ID, depending on the destination type
 * @piority: Priority selection within the DPIO or DPCON channel; valid values
 *		are 0-1 or 0-7, depending on the number of priorities in that
 *		channel; not relevant for 'DPDCEI_DEST_NONE' option
 */
struct dpdcei_dest_cfg {
	enum dpdcei_dest dest_type;
	int dest_id;
	uint8_t priority;
};

/* DPDCEI queue modification options */

/* Select to modify the user's context associated with the queue */
#define DPDCEI_QUEUE_OPT_USER_CTX	0x00000001

/* Select to modify the queue's destination */
#define DPDCEI_QUEUE_OPT_DEST		0x00000002

/**
 * struct dpdcei_rx_queue_cfg - RX queue configuration
 * @options: Flags representing the suggested modifications to the queue;
 *	Use any combination of 'DPDCEI_QUEUE_OPT_<X>' flags
 * @usec_ctx: User context value provided in the frame descriptor of each
 *	dequeued frame;
 *	valid only if 'DPDCEI_QUEUE_OPT_USER_CTX' is contained in 'options'
 * @dest_cfg: Queue destination parameters;
 *	valid only if 'DPDCEI_QUEUE_OPT_DEST' is contained in 'options'
 */
struct dpdcei_rx_queue_cfg {
	u32 options;
	uint64_t user_ctx;
	struct dpdcei_dest_cfg dest_cfg;
};

/**
 * dpdcei_set_rx_queue() - Set Rx queue configuration
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @cfg: Rx queue configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_set_rx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			const struct dpdcei_rx_queue_cfg *cfg);

/**
 * struct dpdcei_rx_queue_attr - Structure representing attributes of Rx queues
 * @user_ctx: User context value provided in the frame descriptor of each
 *		 dequeued frame
 * @dest_cfg: Queue destination configuration
 * @fqid: Virtual FQID value to be used for dequeue operations
 */
struct dpdcei_rx_queue_attr {
	uint64_t user_ctx;
	struct dpdcei_dest_cfg dest_cfg;
	u32 fqid;
};

/**
 * dpdcei_get_rx_queue() - Retrieve Rx queue attributes.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @attr:	Returned Rx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_rx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			struct dpdcei_rx_queue_attr *attr);

/**
 * struct dpdcei_tx_queue_attr - Structure representing attributes of Tx queues
 * @fqid: Virtual FQID to be used for sending frames to DCE hardware
 */
struct dpdcei_tx_queue_attr {
	u32 fqid;
};

/**
 * dpdcei_get_tx_queue() - Retrieve Tx queue attributes.
 * @mc_io	Pointer to MC portal's I/O object
 * @token	Token of DPDCEI object
 * @attr: Returned Tx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpdcei_get_tx_queue(struct fsl_mc_io *mc_io, uint16_t token,
			struct dpdcei_tx_queue_attr *attr);

#endif /* __FSL_DPDCEI_H */
