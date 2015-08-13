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
#ifndef __FSL_DPSECI_H
#define __FSL_DPSECI_H

/* Data Path SEC Interface API
 * Contains initialization APIs and runtime control APIs for DPSECI
 */

struct fsl_mc_io;

/* General DPSECI macros */

/* Maximum number of Tx/Rx priorities per DPSECI object */
#define DPSECI_PRIO_NUM		8

/* All queues considered; see dpseci_set_rx_queue() */
#define DPSECI_ALL_QUEUES	(uint8_t)(-1)

/**
 * dpseci_open() - Open a control session for the specified object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @dpseci_id:	DPSECI unique ID
 * @token:	Returned token; use in subsequent API calls
 *
 * This function can be used to open a control session for an
 * already created object; an object may have been declared in
 * the DPL or by calling the dpseci_create() function.
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent commands for
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_open(struct fsl_mc_io	*mc_io,
		uint32_t		cmd_flags,
		int			dpseci_id,
		uint16_t		*token);

/**
 * dpseci_close() - Close the control session of the object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 *
 * After this function is called, no further operations are
 * allowed on the object without opening a new control session.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_close(struct fsl_mc_io	*mc_io,
		 uint32_t		cmd_flags,
		 uint16_t		token);

/**
 * struct dpseci_cfg - Structure representing DPSECI configuration
 *	@num_tx_queues: num of queues towards the SEC
 *	@num_rx_queues: num of queues back from the SEC
 *  @priorities: Priorities for the SEC hardware processing;
 *		each place in the array is the priority of the tx queue
 *		towards the SEC,
 *		valid priorities are configured with values 1-8;
 */
struct dpseci_cfg {
	uint8_t num_tx_queues;
	uint8_t num_rx_queues;
	uint8_t priorities[DPSECI_PRIO_NUM];
};

/**
 * dpseci_create() - Create the DPSECI object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @cfg:	Configuration structure
 * @token:	Returned token; use in subsequent API calls
 *
 * Create the DPSECI object, allocate required resources and
 * perform required initialization.
 *
 * The object can be created either by declaring it in the
 * DPL file, or by calling this function.
 *
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent calls to
 * this specific object. For objects that are created using the
 * DPL file, call dpseci_open() function to get an authentication
 * token first.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_create(struct fsl_mc_io		*mc_io,
		  uint32_t			cmd_flags,
		  const struct dpseci_cfg	*cfg,
		  uint16_t			*token);

/**
 * dpseci_destroy() - Destroy the DPSECI object and release all its resources.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 *
 * Return:	'0' on Success; error code otherwise.
 */
int dpseci_destroy(struct fsl_mc_io	*mc_io,
		   uint32_t		cmd_flags,
		   uint16_t		token);

/**
 * dpseci_enable() - Enable the DPSECI, allow sending and receiving frames.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_enable(struct fsl_mc_io	*mc_io,
		  uint32_t		cmd_flags,
		  uint16_t		token);

/**
 * dpseci_disable() - Disable the DPSECI, stop sending and receiving frames.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_disable(struct fsl_mc_io	*mc_io,
		   uint32_t		cmd_flags,
		   uint16_t		token);

/**
 * dpseci_is_enabled() - Check if the DPSECI is enabled.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @en:		Returns '1' if object is enabled; '0' otherwise
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_is_enabled(struct fsl_mc_io	*mc_io,
		      uint32_t		cmd_flags,
		      uint16_t		token,
		      int		*en);

/**
 * dpseci_reset() - Reset the DPSECI, returns the object to initial state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_reset(struct fsl_mc_io	*mc_io,
		 uint32_t		cmd_flags,
		 uint16_t		token);

/**
 * struct dpseci_irq_cfg - IRQ configuration
 * @addr:	Address that must be written to signal a message-based interrupt
 * @val:	Value to write into irq_addr address
 * @user_irq_id: A user defined number associated with this IRQ
 */
struct dpseci_irq_cfg {
	     uint64_t		addr;
	     uint32_t		val;
	     int		user_irq_id;
};

/**
 * dpseci_set_irq() - Set IRQ information for the DPSECI to trigger an interrupt.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @irq_index:	Identifies the interrupt index to configure
 * @irq_cfg:	IRQ configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_set_irq(struct fsl_mc_io		*mc_io,
		   uint32_t			cmd_flags,
		   uint16_t			token,
		   uint8_t			irq_index,
		   struct dpseci_irq_cfg	*irq_cfg);

/**
 * dpseci_get_irq() - Get IRQ information from the DPSECI
 *
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @irq_index:	The interrupt index to configure
 * @type:	Interrupt type: 0 represents message interrupt
 *		type (both irq_addr and irq_val are valid)
 * @irq_cfg:	IRQ attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_irq(struct fsl_mc_io		*mc_io,
		   uint32_t			cmd_flags,
		   uint16_t			token,
		   uint8_t			irq_index,
		   int				*type,
		   struct dpseci_irq_cfg	*irq_cfg);

/**
 * dpseci_set_irq_enable() - Set overall interrupt state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
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
int dpseci_set_irq_enable(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint8_t		en);

/**
 * dpseci_get_irq_enable() - Get overall interrupt state
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
 * @irq_index:	The interrupt index to configure
 * @en:			Returned Interrupt state - enable = 1, disable = 0
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_irq_enable(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint8_t		*en);

/**
 * dpseci_set_irq_mask() - Set interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
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
int dpseci_set_irq_mask(struct fsl_mc_io	*mc_io,
			uint32_t		cmd_flags,
			uint16_t		token,
			uint8_t		irq_index,
			uint32_t		mask);

/**
 * dpseci_get_irq_mask() - Get interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
 * @irq_index:	The interrupt index to configure
 * @mask:		Returned event mask to trigger interrupt
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_irq_mask(struct fsl_mc_io	*mc_io,
			uint32_t		cmd_flags,
			uint16_t		token,
			uint8_t		irq_index,
			uint32_t		*mask);

/**
 * dpseci_get_irq_status() - Get the current status of any pending interrupts
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
 * @irq_index:	The interrupt index to configure
 * @status:		Returned interrupts status - one bit per cause:
 *					0 = no interrupt pending
 *					1 = interrupt pending
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_irq_status(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  uint8_t		irq_index,
			  uint32_t		*status);

/**
 * dpseci_clear_irq_status() - Clear a pending interrupt's status
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:		Token of DPSECI object
 * @irq_index:	The interrupt index to configure
 * @status:		bits to clear (W1C) - one bit per cause:
 *					0 = don't change
 *					1 = clear status bit
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_clear_irq_status(struct fsl_mc_io	*mc_io,
			    uint32_t		cmd_flags,
			    uint16_t		token,
			    uint8_t		irq_index,
			    uint32_t		status);

/**
 * struct dpseci_attr - Structure representing DPSECI attributes
 * @id: DPSECI object ID
 * @version: DPSECI version
 * @num_tx_queues: number of queues towards the SEC
 * @num_rx_queues: number of queues back from the SEC
 */
struct dpseci_attr {
	int		id;
	/**
	 * struct version - DPSECI version
	 * @major: DPSECI major version
	 * @minor: DPSECI minor version
	 */
	struct {
		uint16_t major;
		uint16_t minor;
	} version;
	uint8_t num_tx_queues;
	uint8_t num_rx_queues;
};

/**
 * dpseci_get_attributes() - Retrieve DPSECI attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @attr:	Returned object's attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_attributes(struct fsl_mc_io	*mc_io,
			  uint32_t		cmd_flags,
			  uint16_t		token,
			  struct dpseci_attr	*attr);

/**
 * enum dpseci_dest - DPSECI destination types
 * @DPSECI_DEST_NONE: Unassigned destination; The queue is set in parked mode
 *		and does not generate FQDAN notifications; user is expected to
 *		dequeue from the queue based on polling or other user-defined
 *		method
 * @DPSECI_DEST_DPIO: The queue is set in schedule mode and generates FQDAN
 *		notifications to the specified DPIO; user is expected to dequeue
 *		from the queue only after notification is received
 * @DPSECI_DEST_DPCON: The queue is set in schedule mode and does not generate
 *		FQDAN notifications, but is connected to the specified DPCON
 *		object; user is expected to dequeue from the DPCON channel
 */
enum dpseci_dest {
	DPSECI_DEST_NONE = 0,
	DPSECI_DEST_DPIO = 1,
	DPSECI_DEST_DPCON = 2
};

/**
 * struct dpseci_dest_cfg - Structure representing DPSECI destination parameters
 * @dest_type: Destination type
 * @dest_id: Either DPIO ID or DPCON ID, depending on the destination type
 * @priority: Priority selection within the DPIO or DPCON channel; valid values
 *	are 0-1 or 0-7, depending on the number of priorities in that
 *	channel; not relevant for 'DPSECI_DEST_NONE' option
 */
struct dpseci_dest_cfg {
	enum dpseci_dest	dest_type;
	int			dest_id;
	uint8_t		priority;
};

/* DPSECI queue modification options */

/* Select to modify the user's context associated with the queue */
#define DPSECI_QUEUE_OPT_USER_CTX	0x00000001

/* Select to modify the queue's destination */
#define DPSECI_QUEUE_OPT_DEST		0x00000002

/* Select to modify the queue's order preservation */
#define DPSECI_QUEUE_OPT_ORDER_PRESERVATION    0x00000004

/**
 * struct dpseci_rx_queue_cfg - DPSECI RX queue configuration
 * @options: Flags representing the suggested modifications to the queue;
 *	Use any combination of 'DPSECI_QUEUE_OPT_<X>' flags
 * @order_preservation_en: order preservation configuration for the rx queue
 * valid only if 'DPSECI_QUEUE_OPT_ORDER_PRESERVATION' is contained in 'options'
 * @user_ctx: User context value provided in the frame descriptor of each
 *	dequeued frame;
 *	valid only if 'DPSECI_QUEUE_OPT_USER_CTX' is contained in 'options'
 * @dest_cfg: Queue destination parameters;
 *	valid only if 'DPSECI_QUEUE_OPT_DEST' is contained in 'options'
 */
struct dpseci_rx_queue_cfg {
	uint32_t options;
	int order_preservation_en;
	uint64_t user_ctx;
	struct dpseci_dest_cfg dest_cfg;
};

/**
 * dpseci_set_rx_queue() - Set Rx queue configuration
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @queue:	Select the queue relative to number of
 *		priorities configured at DPSECI creation; use
 *		DPSECI_ALL_QUEUES to configure all Rx queues identically.
 * @cfg:	Rx queue configuration
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_set_rx_queue(struct fsl_mc_io			*mc_io,
			uint32_t				cmd_flags,
			uint16_t				token,
			uint8_t					queue,
			const struct dpseci_rx_queue_cfg	*cfg);

/**
 * struct dpseci_rx_queue_attr - Structure representing attributes of Rx queues
 * @user_ctx: User context value provided in the frame descriptor of each
 *	dequeued frame
 * @order_preservation_en: Status of the order preservation configuration
 *				on the queue
 * @dest_cfg: Queue destination configuration
 * @fqid: Virtual FQID value to be used for dequeue operations
 */
struct dpseci_rx_queue_attr {
	uint64_t		user_ctx;
	int			order_preservation_en;
	struct dpseci_dest_cfg	dest_cfg;
	uint32_t		fqid;
};

/**
 * dpseci_get_rx_queue() - Retrieve Rx queue attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @queue:	Select the queue relative to number of
 *				priorities configured at DPSECI creation
 * @attr:	Returned Rx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_rx_queue(struct fsl_mc_io		*mc_io,
			uint32_t			cmd_flags,
			uint16_t			token,
			uint8_t				queue,
			struct dpseci_rx_queue_attr	*attr);

/**
 * struct dpseci_tx_queue_attr - Structure representing attributes of Tx queues
 * @fqid: Virtual FQID to be used for sending frames to SEC hardware
 * @priority: SEC hardware processing priority for the queue
 */
struct dpseci_tx_queue_attr {
	uint32_t fqid;
	uint8_t priority;
};

/**
 * dpseci_get_tx_queue() - Retrieve Tx queue attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPSECI object
 * @queue:	Select the queue relative to number of
 *				priorities configured at DPSECI creation
 * @attr:	Returned Tx queue attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpseci_get_tx_queue(struct fsl_mc_io		*mc_io,
			uint32_t			cmd_flags,
			uint16_t			token,
			uint8_t				queue,
			struct dpseci_tx_queue_attr	*attr);

#endif /* __FSL_DPSECI_H */
