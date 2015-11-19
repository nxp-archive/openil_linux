/* Copyright (C) 2015 Freescale Semiconductor, Inc.
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
 * Assumptions:
 * - Currently we allocate one SCF per frame list to DCE
 *   FIXME: this allocation is slow and should not be on the data path
 * - There is no need for supporting BMan in the convenience functions *_data
 *   like process_data() and its associated callback, because if contiguous
 *   memory is given, contiguous memory should be returned. BMan buffers will be
 *   tough to glue into one contiguous map
 * - A DCE API session will only need to serve one callback form. There are
 *   currently two callback forms, process_frame, and process_data
 */


#include "dpdcei-drv.h"
#include "dce-fd.h"
#include "dce-fd-frc.h"


/**
 * DOC: The DCE API - A reentrant simplified interface to DCE
 *
 * DOC: Goal:
 *  This API was designed to simplify interaction with DCE as much as possible
 *  without loss of flexibility and acceleration offered by DCE hardware
 *
 * DOC: Theory of operation:
 *  A user creates a session object to process multiple pieces of similar data
 *  on DCE.  All subsequent interaction is done through this session. One
 *  session can be used concurrently, if order is not necessary. Multiple
 *  sessions can be used simultaneously
 */

/* TODO: Must include this information in header file. Plan is not to rely on
 * the block guide
 * Expected user knowledge:
 * Users of the API must have a basic understanding of DCE interface to
 * be able to select the correct flags and supply the right input/output based
 * on DCE specific response codes. In addition to this header file, the user
 * should have read the `System Interface' section of the DCE block guide.
 * Special attention should be given to the following sections. `PROCESS
 * command', `Frame Processing Modes', `Multiple Members Input
 * Frames', `Status Code Enumeration', `zlib Flush Semantics'
 */


/**
 * enum dce_engine - The engine to use for session operations
 * @DCE_COMPRESSION:	Compression engine
 * @DCE_DECOMPRESSION:	Decompression engine
 */
enum dce_engine {
	DCE_COMPRESSION,
	DCE_DECOMPRESSION
};

/**
  * enum dce_paradigm - The way to handle multi-frame requests
  * @DCE_SESSION_STATELESS:	All requests will be self contained
  * @DCE_SESSION_STATEFUL_TRUNCATION:	Requests resulting in exceptions will be
  *					truncated
  * @DCE_SESSION_STATEFUL_RECYCLE:	Requests resulting in exceptions will
  *					cause suspension and allow recovery
  */
enum dce_paradigm {
	DCE_SESSION_STATELESS = 0,
	DCE_SESSION_STATEFUL_TRUNCATION = 1,
	DCE_SESSION_STATEFUL_RECYCLE = 2
};

/**
 * enum dce_compression_format - The compression formats supported by DCE
 * @DCE_SESSION_CF_DEFLATE:	Raw deflate, see RFC 1951
 * @DCE_SESSION_CF_ZLIB:	zlib, see RFC 1950
 * @DCE_SESSION_CF_GZIP:	gzip, see RFC 1952
 */
enum dce_compression_format {
	DCE_SESSION_CF_DEFLATE = 0,
	DCE_SESSION_CF_ZLIB = 1,
	DCE_SESSION_CF_GZIP = 2
};

/**
 * enum dce_compression_effort - Level of compression to perform
 * @DCE_SESSION_CE_NONE:	No compression, just add appropriate headers
 * @DCE_SESSION_CE_STATIC_HUFF_STRMATCH:	Static Huffman & string matching
 * @DCE_SESSION_CE_HUFF_ONLY:	Huffman only
 * @DCE_SESSION_CE_BEST_POSSIBLE:	Best possible compression
 */
enum dce_compression_effort {
	DCE_SESSION_CE_NONE = 0,
	DCE_SESSION_CE_STATIC_HUFF_STRMATCH = 1,
	DCE_SESSION_CE_HUFF_ONLY = 2,
	DCE_SESSION_CE_BEST_POSSIBLE = 3,
};

/**
 * enum dce_flush_parameter - Data flushing modes
 * @DCE_Z_NO_FLUSH:	equivalent to Z_NO_FLUSH
 * @DCE_Z_PARTIAL_FLUSH:	equivalent to Z_PARTIAL_FLUSH
 * @DCE_Z_SYNC_FLUSH:	equivalent to Z_PARTIAL_FLUSH
 * @DCE_Z_FULL_FLUSH:	equivalent to Z_SYNC_FLUSH
 * @DCE_Z_FINISH:	equivalent to Z_FULL_FLUSH
 * @DCE_Z_BLOCK:	equivalent to Z_BLOCK
 * @DCE_Z_TREES:	equivalent to Z_TREES
 *
 * These flush parameters are parallel to the zlib standard
 */
enum dce_flush_parameter {
	DCE_Z_NO_FLUSH = 0x0,
	DCE_Z_PARTIAL_FLUSH = 0x1,
	DCE_Z_SYNC_FLUSH = 0x2,
	DCE_Z_FULL_FLUSH = 0x3,
	DCE_Z_FINISH = 0x4,
	DCE_Z_BLOCK = 0x5,
	DCE_Z_TREES = 0x6
};

/**
 * struct dce_gz_header - gzip header and state for gzip streams
 * @text:	True if compressed data is believed to be text
 * @time:	Modification time
 * @xflags:	Extra flags indicating compression level (not used when
 *		writing a gzip file)
 * @os:		operating system
 * @meta_data:	Contiguous memory for storing meta data like name and comment
 * @extra_len:	`extra' field length
 * @name_len:	`name' field length
 * @comment_len:	`comment' field length
 * @meta_max:	Space available at meta_data
 * @hcrc:	true if there was or will be a header crc
 * @done:	true when done reading gzip header
 *
 * The gzip compression format documented in RFC 1952 includes a header for each
 * gzip member.
 */
struct dce_gz_header {
	int text; /* True if compressed data believed to be text */
	unsigned long time; /* Modification time */
	int xflags; /* Extra flags indicating compression level (not used when
		       writing a gzip file) */
	int os; /* operating system */
	dma_addr_t meta_data; /* Compression: dma to `extra' field, `name'
				 field, and `comment' field. `name' and
				 `comment' fields must be zero terminated.
				 meta_data must be set to NULL if none of the
				 fields are present
				 Decompression: dma to `extra' field, `name'
				 field, and comment field. meta_data must be
				 set to NULL if fields are not needed. Fields
				 will be discarded */
	unsigned int extra_len; /* Compression: `extra' field length in
				   meta_data
				   Decompression: Length of the `extra' field
				   (valid if meta_data != NULL) */
	unsigned int name_len; /* Compression: `name' field length in meta_data
				  Decompression: Length of the `name' field
				  (valid if meta_data != NULL) */
	unsigned int comment_len; /* Compression: `comment' field length in
				     meta_daata
				     Decompression: Length of the `comment'
				     field
				     (valid if meta_data != NULL) */
	unsigned int meta_max; /* Space at meta_data (when reading header) */
	int hcrc; /* true if there was or will be a header crc */
	int done; /* true when done reading gzip header (not used when writing a
		     gzip file) */
};

struct dce_session;

/**
 * \typedef dce_callback_frame
 * \brief Return result of a (de)compress dce_process_frame() call
 * @session:	Pointer to session struct for which response was received from
 *		DCE
 * @status:	The status returned by DCE
 * @input_fd:	Pointer to the input frame. NB: The FD pointed to is no
 *		persistent. A copy should be made by the callback if the
 *		preservation of the FD is needed
 * @output_fd:	Pointer to output FD. Same consideration as @input_fd
 * @input_consumed:	Number of bytes used in creating output
 * @output_produced:	Number of bytes produced
 * @context:	Pointer to user defined object received in dce_process_frame()
 *		call
 */
typedef void (*dce_callback_frame)(struct dce_session *session,
		uint8_t status,
		struct dpaa2_fd *input_fd,
		struct dpaa2_fd *output_fd,
		size_t input_consumed,
		void *context);

/**
 * \typedef dce_callback_data
 * \brief Return result of a (de)compress dce_process_data() call
 * @session:	Pointer to session struct for which response was received from
 *		DCE
 * @status:	The status returned by DCE
 * @input:	Input pointer as received by the API in dce_process_data() call
 * @output:	Output pointer to resulting data
 * @input_consumed:	Number of bytes used in creating output
 * @output_produced:	Number of bytes produced
 * @context:	Pointer to user defined object received in dce_process_data()
 *		call
 */
typedef void (*dce_callback_data)(struct dce_session *session,
		uint8_t status,
		dma_addr_t input,
		dma_addr_t output,
		size_t input_consumed,
		size_t output_produced,
		void *context);

/**
 * struct dce_session_params - parameters used in initialisation of dce_session
 * @engine	: compression or decompression
 * @paradigm	: statefull_recycle, statefull_truncate, or stateless
 * @compression_format	: gzip, zlib, deflate
 * @compression_effort	: compression effort from none to best possible
 * @gz_header	: Pointer to gzip header. Valid in gzip mode only
 * @callback_frame	: User defined callback function for receiving responses
 *			  from dce_process_frame()
 * @callback_data	: User defined callback function for receiving responses
 *			  from dce_process_frame()
 */

struct dce_session_params {
	enum dce_engine engine; /* compression or decompression */
	enum dce_paradigm paradigm; /* statefull_recycle, statefull_truncate,
				     * or stateless */
	/* gzip, zlib, deflate */
	enum dce_compression_format compression_format;
	enum dce_compression_effort compression_effort; /* compression effort */
	struct dce_gz_header *gz_header; /* Valid in gzip mode. Should be NULL
					  * in all other modes
					  * Compression: Pointer to gzip header
					  * with appropriate values to use for
					  * setting up gzip member headers
					  * Decompression: Pointer to gzip
					  * struct in which to place read
					  * headers
					  * NB: Header must be persistent until
					  * session_destroy() */
	/* TODO: must figure out how buffer pool support works. Who populates it
	 * who frees buffers? Who knows the buffer size ... could cause a change
	 * in API */
	unsigned buffer_pool_id; /* Not supported in current hardware */
	unsigned buffer_pool_id2; /* Not supported in current hardware */
	bool release_buffers; /* Not supported in current hardware */
	bool encode_base_64; /* session will handle 64 bit encoded data */
	/* User defined callback function for dce_process_frame() result */
	dce_callback_frame callback_frame;
	/* User defined callback function for dce_process_data() result */
	dce_callback_data callback_data;
};

/* FIXME: these two structs were originally in the dce.c moved here because I
 * needed to declare the struct in my application that uses dce. Not sure if
 * there is a better way that allows the application to struct the objects */
struct dma_hw_mem {
	void *vaddr;
	size_t len;
	dma_addr_t paddr;
};
/* dce_session - struct used to keep track of session state. This struct is not
 * visible to the user */
struct dce_session {
	enum dce_engine engine;
	enum dce_paradigm paradigm;
	enum dce_compression_format compression_format;
	enum dce_compression_effort compression_effort;
	struct dce_gz_header *gz_header;
	unsigned buffer_pool_id;
	unsigned buffer_pool_id2;
	bool release_buffers;
	bool encode_base_64;
	dce_callback_frame callback_frame;
	dce_callback_data callback_data;
	struct fsl_mc_device *device;
	struct dce_flow flow;
	struct kmem_cache *pending_cache;
	struct kmem_cache *history_cache;
	struct kmem_cache *context_cache;
	struct kmem_cache *work_cache;
	struct dma_hw_mem pending_output;
	struct dma_hw_mem history;
	struct dma_hw_mem decomp_context;
};

/**
 * dce_session_create() - Initialise a session for compression or decompression
 * @session:	Pointer to a session struct to be initialised
 * @params:	Pointer to a params struct to be used in configuring the session
 *
 * Contextual information is stored opaquely in the session object, such as the
 * buffer pool id to use for getting buffers, the gzip header pointer to info
 * such as the ID1 ID2 CM FLG MTIME XFL OS fields. A session is setup then used
 * to send many requests to DCE
 *
 * Return:	0 on success, error otherwise
 */
int dce_session_create(struct dce_session *session,
		       struct dce_session_params *params);

/** dce_session_device - gets the (de)compression device used in the session
 * @session:	Pointer to a session struct from which to get a device
 *
 * Can be used by the DCE caller to dma map memory to the device before passing
 * it to the process functions
 *
 * Return:	Pointer to device. NULL pointer if error
 */
struct fsl_mc_device *dce_session_device(struct dce_session *session);


/**
 * dce_session_destroy() - cleanup and release resources held by session
 * @session:	Pointer to a session to be retired
 *
 * This function checks for work units in flight and make sure that there is no
 * attempt to cleanup a session while WIP
 *
 * Return:	0 on success, -EACCES if there is still work in progress
 */
int dce_session_destroy(struct dce_session *session);


/**
 * dce_process_frame() - Compress or decompress a frame asynchronously
 * @session:	Pointer to session struct on which to send (de)compress requests
 * @input_fd:	Pointer to a FD that contains the input data
 * @output_fd:	Pointer to a FD that has the output buffer. If this parameter is
 *		NULL then the buffer pool associated with the session to acquire
 *		buffers as necessary
 * @flush:	Flush behaviour for the request using zLib semantics
 * @initial_frame:	Indicates that this is the first frame in a flow
 * @recycled_frame:	Indicates this frame is a response to a session suspend
 * @context:	Pointer to a caller defined object that is returned in dequeue
 *
 * More on @context
 * The caller can point context at a meaningful object to allow the user defined
 * callback to take some useful action. e.g. Wakeup a sleeping thread, pass on
 * some information about the destination for the data
 *
 * Return:	0 on success,
 *		-EBUSY if the device is busy and call must be reattempted
 */
int dce_process_frame(struct dce_session *session,
		      struct dpaa2_fd *input_fd,
		      struct dpaa2_fd *output_fd,
		      enum dce_flush_parameter flush,
		      bool initial_frame,
		      bool recycled_frame,
		      void *context);


/**
 * dce_process_data() - Compress or decompress arbitrary data asynchronously
 * @session:	Pointer to a session struct on which to send (de)compress
 *		requests
 * @input:	DMA address to input data, can be NULL if final input was
 *		passed in the previous process calls
 * @output:	DMA address to output buffer, must not be NULL
 * @input_len:	Size of the data for input
 * @output_len:	Size of the output buffer available. BMan output is not
 *		supported in rev 1 silicon. The size currently must be greater
 *		than 0
 * @flush:	Flush behaviour for the request using zLib semantics
 * @initial_request:	Indicates that this is the first frame in a flow
 * @recycled_request:	Indicates this frame is a response to a session suspend
 * @context:	Pointer to a caller defined object that is returned in dequeue
 *
 * More on @context
 * The caller can point context at a meaningful object to allow the user defined
 * callback to take some useful action. e.g. Wakeup a sleeping thread, pass on
 * some information about where is the destination for the data.
 *
 * Return:	0 on success,
 *		-EBUSY if the device is busy and call must be reattempted
 */
int dce_process_data(struct dce_session *session,
		     dma_addr_t input,
		     dma_addr_t output,
		     size_t input_len,
		     size_t output_len,
		     enum dce_flush_parameter flush,
		     bool initial_request,
		     bool recycled_request,
		     void *context);


/**
 * dce_gz_header_update() - Notify session of a gzip header update
 * @session: Pointer to a session struct that must be notified of the header
 *	     update
 *
 * This function is only valid for Compression sessions
 * Return: 0 on success,
 *	   -EBUSY if the device is busy and call must be reattempted
 *	   -EINVAL if the session is not in gzip mode, is a decompression
 *	   session, or a stateless compression session. For stateless
 *	   compression sessions the gzip header will be updated automatically
 *	   with every call to dce_process_frame() or dce_process_data()
 */
int dce_gz_header_update(struct dce_session *session);


/* Maybe add a scatter gather version of process to handle kernel scatter
 * gather */
