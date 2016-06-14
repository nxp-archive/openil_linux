#ifndef _CONFIG_H_
#define _CONFIG_H_
#define CFG_WIFI_OFFLOAD		(1 << 1)
#define CFG_ICC		(1 << 11)
#define CFG_RTP		(1 << 14)
#define CFG_ELLIPTIC		(1 << 15)
#define CFG_ALL			(0 |  CFG_WIFI_OFFLOAD |  CFG_ICC |  CFG_RTP |  CFG_ELLIPTIC )
#endif /* _CONFIG_H_ */
