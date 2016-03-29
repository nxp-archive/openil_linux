/*
 * Copyright 2013 Freescale Semiconductor, Inc.
 */

#ifndef FL_BITFIELD_MACROS_H
#define FL_BITFIELD_MACROS_H

/*
 *  macro to generate a field. This field can be part of a register or other
 *  defined structure
 */
#define FL_FGEN(field, value) \
	(((value) << field##_SHIFT) & field##_MASK)

/* macro which generates field based on a token value */
#define FL_FGENTK(field, token) \
	FL_FGEN(field, field##_##token)

/**
 * SET_BFXX(v, m, x) - Returns the result of setting value [x] into bit
 * field [m] of value [v]
 *
 * [m] identifies the bit field and it is assumed that there exists
 * two macros: m_MASK and m_SHIFT. The former contains the bit mask;
 * the latter contains the number of least-significant zero bits in
 * the mask.
 * XX idenfies the width of the value and destination
 *
 * _IDX is a variant where a this idenfies an index into a array. The
 * macros expects a define of field_XXIDX to be defined where XX is inline
 * with the XX type (8, 16, 32, 64). This is useful when using dma stuctures.
 */
#define SET_BF64(dest, field, value)	\
	(dest = \
	((dest & ~field##_MASK) | ((((u64)value) << field##_SHIFT) & \
					field##_MASK)))

#define SET_BF64_IDX(dest, field, value)	\
	((*(dest+field##_64IDX)) = \
	(((*(dest+field##_64IDX)) & ~field##_MASK) | \
			(((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF64_TK(dest, field, token)	\
	(dest = \
	((dest & ~field##_MASK) | ((field##_##token << field##_SHIFT) & \
					field##_MASK)))

#define SET_BF64_TK_IDX(dest, field, token)	\
	((*(dest+field##_64IDX)) = \
	(((*(dest+field##_64IDX)) & ~field##_MASK) | \
			((field##_##token << field##_SHIFT) & field##_MASK)))

#define SET_BF32(dest, field, value) \
	(dest = \
	((dest & ~field##_MASK) | (((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF32_IDX(dest, field, value) \
	((*(dest+field##_32IDX)) = \
	(((*(dest+field##_32IDX)) & ~field##_MASK) | \
			(((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF32_TK(dest, field, token)	\
	(dest = \
	((dest & ~field##_MASK) | ((field##_##token << field##_SHIFT) & \
			field##_MASK)))

#define SET_BF32_TK_IDX(dest, field, token)	\
	((*(dest+field##_32IDX)) = \
	(((*(dest+field##_32IDX)) & ~field##_MASK) | \
			((field##_##token << field##_SHIFT) & field##_MASK)))

#define SET_BF16(dest, field, value)	\
	(dest = \
	((dest & ~field##_MASK) | (((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF16_IDX(dest, field, value)	\
	((*(dest+field##_16IDX)) = \
	(((*(dest+field##_16IDX)) & ~field##_MASK) | \
			(((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF16_TK(dest, field, token)	\
	(dest = \
	((dest & ~field##_MASK) | ((field##_##token << field##_SHIFT) & \
			field##_MASK)))

#define SET_BF16_TK_IDX(dest, field, token)	\
	((*(dest+field##_16IDX)) = \
	(((*(dest+field##_16IDX)) & ~field##_MASK) | \
			((field##_##token << field##_SHIFT) & field##_MASK)))

#define SET_BF8(dest, field, value)	\
	(dest = \
	((dest & ~field##_MASK) | (((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF8_IDX(dest, field, value)	\
	((*(dest+field##_8IDX)) = \
	(((*(dest+field##_8IDX)) & ~field##_MASK) | \
			(((value) << field##_SHIFT) & field##_MASK)))

#define SET_BF8_TK(dest, field, token)	\
	(dest = \
	((dest & ~field##_MASK) | ((field##_##token << field##_SHIFT) & \
			field##_MASK)))

#define SET_BF8_TK_IDX(dest, field, token)	\
	((*(dest+field##_8IDX)) = \
	(((*(dest+field##_8IDX)) & ~field##_MASK) | \
			((field##_##token << field##_SHIFT) & field##_MASK)))

/**
 * GET_BF(v, m) - Gets the value in bit field [m] of expression [v]
 *
 * [m] identifies the bit field and it is assumed that there exists
 * two macros: m_MASK and m_SHIFT. The former contains the bit mask;
 * the latter contains the number of least-significant zero bits in
 * the mask.
 */
#define GET_BF64(source, field)	\
	((source & field##_MASK) >> field##_SHIFT)

#define GET_BF64_IDX(source, field) \
	(((*(source+field##_64IDX)) & field##_MASK) >> field##_SHIFT)

#define GET_BF32(source, field)	\
	((source & field##_MASK) >> field##_SHIFT)

#define GET_BF32_IDX(source, field) \
	(((*(source+field##_32IDX)) & field##_MASK) >> field##_SHIFT)

#define GET_BF16(source, field)	\
	((source & field##_MASK) >> field##_SHIFT)

#define GET_BF16_IDX(source, field) \
	(((*(source+field##_16IDX)) & field##_MASK) >> field##_SHIFT)

#define GET_BF8(source, field)	\
	((source & field##_MASK) >> field##_SHIFT)

#define GET_BF8_IDX(source, field) \
	(((*(source+field##_8IDX)) & field##_MASK) >> field##_SHIFT)

/* Register field is-equal based on token (enum) */
#define ISEQ_32FTK(source, reg_field, token) \
	(GET_BF32((source), reg_field) == reg_field##_##token)

#endif		/* FL_BITFIELD_MACROS */
