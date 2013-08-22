#
# Makefile for Freesecale DCE driver
#

obj-$(CONFIG_FSL_DCE) += fsl-dce.o
obj-$(CONFIG_FSL_DCE_CONFIG) += fsl-dce-config.o
obj-$(CONFIG_FSL_DCE_DEBUGFS) += fsl-dce-debugfs.o

fsl-dce-y := dce_sys.o flib/dce_flow.o fsl_dce_chunk.o fsl_dce_stream.o
fsl-dce-config-y := dce_driver.o
fsl-dce-debugfs-y := dce_debugfs.o

