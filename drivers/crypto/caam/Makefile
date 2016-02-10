#
# Makefile for the CAAM backend and dependent components
#
ifeq ($(CONFIG_CRYPTO_DEV_FSL_CAAM_DEBUG), y)
	EXTRA_CFLAGS := -DDEBUG
endif

obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM) += caam.o
obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_JR) += caam_jr.o
obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API) += caamalg.o
obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_QI) += caamalg_qi.o
obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_AHASH_API) += caamhash.o
obj-$(CONFIG_CRYPTO_DEV_FSL_CAAM_RNG_API) += caamrng.o

caam-objs := ctrl.o
caam_jr-objs := jr.o key_gen.o error.o
ifneq ($(CONFIG_CRYPTO_DEV_FSL_CAAM_CRYPTO_API_QI),)
	ccflags-y += -DCONFIG_CAAM_QI
	caam-objs += qi.o
endif

obj-$(CONFIG_FSL_CAAM_PKC_SUPPORT) += caam_pkc.o
caam_pkc-objs := caampkc.o pkc_desc.o
