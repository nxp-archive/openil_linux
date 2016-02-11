/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef FL_DCE_GZIP_HELPER_H
#define FL_DCE_GZIP_HELPER_H

#include "dce_defs.h"

/* GZIP constants */
#define GZIP_ID1	0x1f
#define GZIP_ID2	0x8b
#define GZIP_ID1_ID2	0x1f8b
#define GZIP_CM_DEFLATE	8

/* GZIP FLaGs settings */
#define GZIP_FLG_FTEXT		0x01
#define GZIP_FLG_FHCRC		0x02
#define GZIP_FLG_FEXTRA		0x04
#define GZIP_FLG_FNAME		0x08
#define GZIP_FLG_FCOMMENT	0x10

/* GZIP XFL */
#define GZIP_XFL_MAX_COMPRESSION	2
#define GZIP_XFL_FASTEST_ALGO		4

/* GZIP OS */
#define GZIP_OS_FAT		0
#define GZIP_OS_AMIGA		1
#define GZIP_OS_VMS		2
#define GZIP_OS_UNIX		3
#define GZIP_OS_VM_CMS		4
#define GZIP_OS_ATARI		5
#define GZIP_OS_HPFS		6
#define GZIP_OS_MACINTOSH	7
#define GZIP_OS_Z_SYSTEM	8
#define GZIP_OS_CP_M		9
#define GZIP_OS_TOPS_20		10
#define GZIP_OS_NTFS		11
#define GZIP_OS_QDOS		12
#define GZIP_OS_ACORN		13
#define GZIP_OS_UNKNOWN		255

/**
 * set_extra_ptr_content - set the content of the extra_ptr
 *
 * @extra_ptr: location where extra_data, comment and filename are located.
 * @extra_ptr_size: number of byte that extra_ptr points to
 * @extra_data: gzip extra data container
 * @extra_data_size: size in bytes to use in extra_data
 * @filename: NULL terminated filename or can be NULL
 * @comment: NULL terminated comment or can be NULL
 *
 * @extra_data_size + strlen(@filename)+1 + strlen(@comment)+1 <= extra_ptr_size
 * return 0 on success
 * NOTE: Don't think I can define this api like this because of dma_add_t.
 * The intent is to copy in contiguous memory first the extra data followed
 * by the file name and then the comment at the extra_ptr location.
 * But I think this has to be cpu address, not dma address.
 */
static inline int set_extra_ptr_content(void *extra_ptr, size_t extra_ptr_size,
	void *extra_data, size_t extra_data_size, char *filename, char *comment)
{
	size_t filename_size = 0, comment_size = 0;

	if (filename)
		filename_size = strlen(filename) + 1;
	if (comment)
		comment_size = strlen(comment) + 1;

	if (extra_ptr_size < extra_data_size + filename_size + comment_size)
		return -EINVAL;
	memcpy(extra_ptr, extra_data, extra_data_size);
	memcpy(extra_ptr + extra_data_size, filename, filename_size);
	memcpy(extra_ptr + extra_data_size + filename_size, comment,
		comment_size);
	return 0;
}

/**
 * init_gzip_header - initialize the gzip header in the stream configuration
 *			stream
 *
 * @scf: A stream configuration frame which is 64 byte aligned and at least
 *	64 bytes in size. The following fields are set:
 *		ID1 = 31
 *		ID2 = 139
 *		CM = 8
 *		FLG, MTIME, XFL, XLEN, NLEN, CLEN = 0
 *		OS = GZIP_OS_UNIX
 *		EXTRA_PTR is left unmodified.
 */
static inline void init_gzip_header(struct scf_64b *scf)
{
	set_id1id2(scf, GZIP_ID1_ID2);
	set_cm(scf, GZIP_CM_DEFLATE);
	set_flg(scf, 0);
	set_mtime(scf, 0);
	set_xfl(scf, GZIP_XFL_MAX_COMPRESSION);
	set_os(scf, GZIP_OS_UNIX);
}

#endif /* FL_DCE_GZIP_HELPER_H */

