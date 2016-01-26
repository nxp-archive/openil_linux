/* Copyright 2013 Freescale Semiconductor, Inc. */

#ifndef DCE_FLOW_H
#define DCE_FLOW_H

#include "dce_defs.h"
#include <linux/fsl_qman.h>
#include <linux/kfifo.h>

/**
 * enum dce_mode - selector for compression or decompression
 * @DCE_COMPRESSION:	mode is compression
 * @DCE_DECOMPRESSIONE:	mode is decompression
 */
enum dce_mode {
	DCE_COMPRESSION,
	DCE_DECOMPRESSION
};

/**
 * enum dce_state_config - Flow configuration
 *
 * @STATEFUL:	Flow is configured as stateful
 * @STATELESS:	Flow is configured as stateless
 *
 * A stateful Flow is a series of non-interleaved (i.e. Frames from different
 * Streams do not interleave within a Flow) Streams to be processed, where a
 * Stream consists of a series of Frames from the same Flow that together
 * comprise a complete entity to be compressed/decompressed (e.g. GZIP member,
 * ZLIB stream, or DEFLATE block). DCE maintains a set of Stream Context values,
 * or state, for each Stream across the individual Frames that comprise it.
 * Thus, an in-order series, or Stream, of Frames, making up a complete entity
 * can be processed over time by DCE without having to be reassembled first.
 * Further, if processing of an individual Frame within the Stream is
 * interrupted due to insufficient output buffer space, DCE provides a
 * mechanism to resume processing of the Stream at a later time with additional
 * output buffer supplied.
 *
 * A stateless Flow is a series of single Frame Streams that are to be
 * processed, but DCE does not maintain any Stream Context between individual
 * Frames. From DCE’s point of view, each dequeued Frame on a stateless
 * Flow is an atomic work unit. If processing of a Frame is interrupted for any
 * reason, DCE returns it with an exception code but does not maintain or update
 * any Stream Context that would allow resumption of processing.
 */
enum dce_state_config {
	DCE_STATEFUL,
	DCE_STATELESS,
};

/**
 * enum dce_processing_mode - mode of behavior when processing statful Flows.
 *
 * @DCE_RECYCLING:	Interrupted streams can be resumed at a later time.
 * @DCE_TRUNCATION:	Interrupted streams cannot be resumed at a later time.
 *
 * When processing of an individual Frame within a Stream is interrupted, due to
 * insufficient output buffer space, on a @DCE_RECYCLING Flow, DCE keeps
 * context to allow later resumption of processing of the Flow.  All
 * subsequently received Frames are returned to software unmodified. This mode
 * thus enables resumption of processing of the interrupted Stream at a later
 * time, even if additional pipelined Frames from the same Flow arrive at DCE
 * after the exception occurs. To resume processing, software resends (recycles)
 * the interrupted Frame, and all subsequently drained Frames, to DCE with an
 * indication that processing of the stream is to be resumed.
 */
enum dce_processing_mode {
	DCE_RECYCLING,
	DCE_TRUNCATION
};

/**
 * enum dce_tsize_coding - Specifies the size of the BMan buffers used to create
 *		scatter/gather tables.
 *
 * @DCE_TSIZE_64B:	4 table entries
 * @DCE_TSIZE_128B:	8 table entries
 * @DCE_TSIZE_256B:	16 table entries
 * @DCE_TSIZE_512B:	32 table entries
 * @DCE_TSIZE_1024B:	64 table entries
 * @DCE_TSIZE_2048B:	128 table entries
 * @DCE_TSIZE_4096B:	256 table entries
 * @DCE_TSIZE_8192B:	512 table entries
 *
 * This value is used in the @dce_bman_cfg structure which is used to configure
 * the usage of BMan when using BMan output buffers.
 */
enum dce_tsize_coding {
	DCE_TSIZE_64B = 0,
	DCE_TSIZE_128B,
	DCE_TSIZE_256B,
	DCE_TSIZE_512B,
	DCE_TSIZE_1024B,
	DCE_TSIZE_2048B,
	DCE_TSIZE_4096B,
	DCE_TSIZE_8192B
};

/**
 * enum dce_compression_format - Specifies the compression format
 *
 * @DCE_CF_DEFLATE:	deflate encoding format
 * @DCE_CF_ZLIB:	zlib encoding format
 * @DCE_CF_GZIP:	gzip encoding format
 *
 * Each PROCESS hardware command received by the DCE hw has a compression format
 * field.
 */
enum dce_compression_format {
	DCE_CF_DEFLATE,
	DCE_CF_ZLIB,
	DCE_CF_GZIP
};

/**
 * struct dce_bman_cfg - configuration for BMan usage
 *
 * @tsize: size of buffers for scatter/gather tables
 * @tbpid: buffer pool id for s/g tables
 * @dmant: data buffer size, mantissa value
 * @dexp: data buffer size, exponent value
 * @dbpid: buffer pool is for data buffer
 *
 * The DCE treats BMan buffers which hold data vs scatter gather tables
 * differently. These can be managed from independent buffer pools.
 */
struct dce_bman_cfg {
	/* scatter gather entries size */
	enum dce_tsize_coding tsize;
	u32 tbpid;
	/* data buffer configuration */
	u32 dmant; /* range 1..16, gets translated internally */
	u32 dexp; /* range 7..22, gets translated internally */
	u32 dbpid;
};

/* predeclaration of structure */
struct fsl_dce_flow;

/* cmd results invoke a user-provided callback of this type */
typedef void (*fsl_dce_base_cb)(struct fsl_dce_flow *, const struct qm_fd *,
			void *callback_tag);
typedef void (*fsl_dce_process_cb)(struct fsl_dce_flow *, const struct qm_fd *,
			void *callback_tag);
typedef void (*fsl_dce_nop_cb)(struct fsl_dce_flow *, const struct qm_fd *,
			void *callback_tag);
typedef void (*fsl_dce_scr_invalidate_cb)(struct fsl_dce_flow *,
			const struct qm_fd *, void *callback_tag);

/**
 * struct fsl_dce_flow_cbs - various command callback functions
 *
 * @process_cb: callback to process command
 * @nop_cb: callback to nop command
 * @scr_invalidate_cb: callback to stream context record invalidate command
 */
struct fsl_dce_flow_cbs {
	fsl_dce_base_cb base_cb;
	fsl_dce_process_cb process_cb;
	fsl_dce_nop_cb nop_cb;
	fsl_dce_scr_invalidate_cb scr_invalidate_cb;
};

/**
 * struct fsl_dce_cmd_token - internal structure used by flow
 *
 * @callback_tag: user supplied void pointer.
 */
struct fsl_dce_cmd_token {
	void *callback_tag;
	u32 flags;
};

/**
 * struct fsl_dce_flow - pair of QMan frame queues which represents a dce flow
 *
 * @fq_tx: dce egress frame queue and associated state change and dequeue
 *	callback functions. This memory must be dma-able.
 * @fq_rx: dce ingress frame queue and associated state change and ern QMan
 *	callback functions. This memory does NOT have to be dma-able.
 * @cbs: callback functions
 * @mode: mode of operation, compression or decompression
 * @bcfg: BMan configuration
 * @actual_fifo_depth: internal fifo length
 * @wanted_fifo_depth: requested size of internal fifo
 * @fifo: A fifo of commands sent to DCE hw
 * @fqtx_id: id of tx fq
 * @fqrx_id: if of rx fq
 * @use_specified_txfq_dest: use the specified @txfq_dest attribute
 * @txfq_dest: the tx fq destination attribute
 * @flags: internal state info
 * @proc_flags: flags used during PROCESS commands
 */
struct fsl_dce_flow {
	struct qman_fq fq_tx;
	struct qman_fq fq_rx;
	struct fsl_dce_flow_cbs cbs;
	enum dce_mode mode;
	struct dce_bman_cfg bcfg;
	u16 actual_fifo_depth;
	u16 wanted_fifo_depth;
	DECLARE_KFIFO_PTR(fifo, struct fsl_dce_cmd_token);
	u32 fqtx_id;
	u32 fqrx_id;
	bool use_specified_txfq_dest;
	u32 txfq_dest;
	u32 flags;
	u32 proc_flags;
};

void fsl_dce_flow_setopt_fqtx_id(struct fsl_dce_flow *flow, u32 id);
void fsl_dce_flow_setopt_fqrx_id(struct fsl_dce_flow *flow, u32 id);
void fsl_dce_flow_setopt_bcfg(struct fsl_dce_flow *flow,
				struct dce_bman_cfg bcfg);
int fsl_dce_flow_setopt_txfqdest(struct fsl_dce_flow *flow, u32 dest);
int fsl_dce_flow_setopt_outputoffset(struct fsl_dce_flow *flow,
				u32 val); /* DCE_PROCESS_OO_*** value */
int fsl_dce_flow_setopt_compression_effort(struct fsl_dce_flow *flow,
				u32 val); /* DCE_PROCESS_CE_*** value */
int fsl_dce_flow_setopt_release_input(struct fsl_dce_flow *flow, bool val);
int fsl_dce_flow_setopt_base64(struct fsl_dce_flow *flow, bool val);

/**
 * struct fsl_dce_flow_init_params - parameters to initialize a dce flow
 *
 * @mode: compression or decompression
 * @cbs: function callbacks
 * @state_config: stateless or statefull
 * @p_mode: truncation mode or recycle mode
 * @fifo_depth: wanted depth in internal fifo
 * @base_cb: Base callback function. QMan will invoke this function callback
 *	on every dequeue from the DCE tx fq.
 * @process_cb: callback function to invoke on completion of process request.
 * @nop_cb: callback function to invoke on completion of nop request.
 * @scr_invalidate_cb: callback function to invoke on completion of a stream
 *	context record invalidate request.
 * @scr: if statefull configuration, dma memory for Stream Context Record
 *	This memory must be 64B aligned. If compression mode must be 64B in
 *	size. If decompression, must be 128B in size.
 */
struct fsl_dce_flow_init_params {
	enum dce_mode mode;
	enum dce_state_config state_config;
	enum dce_processing_mode p_mode;
	u16 fifo_depth;
	fsl_dce_base_cb base_cb;
	fsl_dce_process_cb process_cb;
	fsl_dce_nop_cb nop_cb;
	fsl_dce_scr_invalidate_cb scr_invalidate_cb;
	dma_addr_t scr;
};

/**
 * fsl_dce_flow_init - Initialize the dce flow
 *
 * @flow: the dce flow object to initialize
 * @params: flow parameters to set.
 *
 * Details of what this api does:
 *	creates the RX Frame Queue. attributes include:
 *		rx_fqid (either supplied or allocated)
 *		consumer is a DCPORTAL (ie. DCE)
 *
 *	creates the TX Frame Queue. attribute include:
 *		tx_fqid (either supplied or allocated)
 *		No Enqueues are permitted.
 *
 *	Initialise RX Frame Queue:
 *		Schedule the frame queue
 *		set context_a field (stream context record pointer) and output
 *			buffer pool attributes
 *		set context_b field (more buffer pool attributes and Tx Frame
 *			Queue Id.
 *		set @flow->fq_rx.dest.channel. Different channel if
 *			compression is being used, vs decompression.
 *
 *	Initialise TX Frame Queue:
 *		Schedules the frame queue
 *		sets the stashing parameters
 *		sets @flow->fq_tx.dest.channel. This is either the local
 *			portal on which this api is being invoked on, or
 *			a channel_pool. If channel pool, the fq is placed in
 *			hold active state.
 */
int fsl_dce_flow_init(struct fsl_dce_flow *flow,
		struct fsl_dce_flow_init_params *params);


/**
 * fsl_dce_flow_fifo_len - Number of elements in the fifo
 *
 * @flow: the dce flow object to query
 *
 * Returns the number of elements in the internal fifo.
 */
int fsl_dce_flow_fifo_len(struct fsl_dce_flow *flow);


/**
 * fsl_dce_flow_finish - Finalize the dce flow
 *
 * @flow: the dce flow object to finalize
 * @flags:
 *
 * The QMan frame queues will be put out-of-service and destroyed.
 */
int fsl_dce_flow_finish(struct fsl_dce_flow *flow, u32 flags);

/* Flags for operations */
#ifdef CONFIG_FSL_DPA_CAN_WAIT
#define DCE_ENQUEUE_FLAG_WAIT		QMAN_ENQUEUE_FLAG_WAIT
#define DCE_ENQUEUE_FLAG_WAIT_INT	QMAN_ENQUEUE_FLAG_WAIT_INT
#endif

/**
 * fsl_dce_process - send a DCE PROCESS request
 *
 * @flow:an initialized dce flow object
 * @flags:
 * @fd: dpaa frame descriptor to enqueue
 * @callback_tag: optional, returned to the user in associated callback function
 *
 * The PROCESS Command invokes DCE’s mission mode operation. It indicates to
 * DCE that the provided Frame structure (simple or compound) is to be
 * processed according to the mode of its Frame Queue channel and the Frame’s
 * associated Stream Context Record, and/or a Stream Configuration Frame. The
 * PROCESS Command is analogous to an invocation of the zlib inflate() or
 * deflate() function call.
 *
 * On a stateful Flow, the DCE will process the provided input Frame,
 * potentially write some produced output data into the output Frame (less any
 * residue data held back), and update the Stream Context Record in
 * anticipation of processing a subsequent PROCESS command on the same Stream.
 *
 * On a stateless Flow, the DCE will attempt to fully process the input Frame
 * and write all produced output data into the output Frame. If the DCE cannot
 * complete processing of the input Frame it is simply returned with an error
 * indication code. No continuation of processing, as is done in a typical zlib
 * function call, is possible using DCE-maintained context.
 *
 * Simple Frames may optionally have their component buffers released to BMan
 * as the Frame is processed.  The simple output Frame that is returned to
 * Software is constructed of buffers that are acquired from BMan.
 *
 * Compound Frames also may optionally have their component buffers released to
 * BMan. Compound output Frames may be pre-built or constructed of buffers that
 * are acquired from BMan.
 *
 * It is valid for DCE to receive a PROCESS Command Frame that has a null or
 * zero-length input buffer or zero-length output buffer. DCE will attempt to
 * process the Frame and update Stream Context Record if necessary.
 *
 * For creating GZIP or ZLIB compressed members, the PROCESS Command relies on
 * the following values in the Stream Configuration Frame, or the Stream Context
 * Record, fields being valid when the initial Frame of a series (i.e. a Stream)
 * of Frames is dequeued from QMan:
 *	- ID1, ID2: Required for compression of GZIP members. Values will be
 *		placed into the created header.
 *	- CM: Required for compression of GZIP or ZLIB members. Value will be
 *		places into the created header. This 8-bit field contains the
 *		8-bit CM field for GZIP compression and the 8-bit CMF field for
 *		ZLIB compression.
 *	- FLG: Required for compression of GZIP or ZLIB members. Value will be
 *		placed into the created header, with unsupported options
 *		overridden to 0 (i.e. FDICT) and computed values overridden by
 *		DCE (i.e. FCHECK).
 *	- MTIME: Only required for creation of GZIP members. Value will be
 *		placed into the created GZIP header.
 *	- XFL: Only required for creation of GZIP members. Value will be placed
 *		into the created GZIP header.
 *	- OS: Only required for creation of GZIP members. Value will be placed
 *		into the created GZIP header.
 *	- XLEN: Only required for creation of GZIP members. If FLG.FEXTRA is set
 *		XLEN bytes of data will be read from EXTRA_PTR and inserted into
 *		the GZIP header.
 *	- NLEN: Only required for creation of GZIP members. If FLG.FNAME is set,
 *		NLEN bytes of data will be read from (EXTRA_PTR + XLEN) and
 *		inserted into the GZIP header. Note that it does not matter
 *		whether or not FLG.FEXTRA is set.
 *	- CLEN: Only required for creation of GZIP members. If FLG.FCOMMENT is
 *		set, CLEN bytes of data will be read from (EXTRA_PTR + XLEN +
 *		NLEN) and inserted into the GZIP header. Note that it does not
 *		matter whether or not FLG.FEXTRA or FLG.FNAME is set.
 *	- EXTRA_PTR: Only required for creation of GZIP members. Only required
 *		if one or more of XLEN, NLEN, or CLEN is non-zero.
 *
 * All other Stream Context Record fields will be initialized by DCE prior to
 * processing the first input Frame (denoted by a set I bit). Any stale values
 * present are ignored and updated afterwards. Note that in order for the
 * created compressed stream to be RFC compliant, care must be taken to ensure
 * that the provisioned header values are consistent with DCE’s output. For
 * example, DCE is only capable of producing GZIP streams with CM=8 and CINFO=4,
 * so these values must be provisioned in order to create properly formed GZIP
 * members.
 *
 * On decompression Flows, DCE validates the received header information found
 * in the first N1 bytes of the Stream for consistency with the CF field
 * setting. Any inconsistencies in the header or unsupported/reserved values
 * present in the STATUS/CMD fields will result in an Invalid STATUS/CMD error
 * or the appropriate GZIP, ZLIB, or DEFLATE header error.  The PROCESS Command
 * supports the same set of flush parameters as zlib inflate() and deflate()
 * calls do.
 */
int fsl_dce_process(struct fsl_dce_flow *flow, u32 flags,
		struct qm_fd *fd, void *callback_tag);

/**
 * fsl_dce_nop - send a DCE NOP request
 *
 * @flow: an initialized dce flow object
 * @flags: bit-mask of  DCE_FLOW_OP_*** options
 * @callback_tag: optional, returned to the user in associated callback function
 *
 * Sends a NOP command to the DCE. The flow must be initialized. Returns
 * zero on success. If no flags are specified the api will return after the
 * command has been enqueued.
 * The NOP Command provides Software with a non-invasive ordering mechanism to
 * ensure that all preceding input Frames from the associated Stream have been
 * fully processed, without needing to send a compress or decompress command
 * through the DCE.
 */
int fsl_dce_nop(struct fsl_dce_flow *flow, u32 flags, void *callback_tag);

/**
 * fsl_dce_scr_invalidate - send a DCE Context Invalidate request
 *
 * @flow: an initiazed dce flow object
 * @flags: bit-mask of  DCE_FLOW_OP_*** options
 * @callback_tag: optional, returned to the user in associated callback function
 *
 * Sends a Context Invalidate command to the DCE. Returns zero on success. If no
 * flags are specified the api will return after the command has been enqueued.
 * The Context Invalidate Command provides Software with a means to invalidate a
 * cached copy of a Stream Context Record in the DCE hardware. The invalidate
 * command guarantees that the system memory locations used by, or referenced
 * by, the context can be returned to Software.  As its name implies, the
 * Context Invalidate command does not cause an updated copy of the Stream
 * Context Record to be written to system memory, so it will cause a loss of
 * information if used in the middle of Stream that is being processed.  This
 * command is only useful when processed on a stateful Flow. If it is received
 * on a stateless Frame Queue it has no effect.
 */
int fsl_dce_scr_invalidate(struct fsl_dce_flow *flow, u32 flags,
			void *callback_tag);

#endif /* DCE_FLOW_H */

