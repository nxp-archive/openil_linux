#ifndef __ASM_IRQ_H
#define __ASM_IRQ_H

#include <linux/irqchip/arm-gic-acpi.h>

#include <asm-generic/irq.h>

/*
 * Use this value to indicate lack of interrupt
 * capability
 */
#ifndef NO_IRQ
#define NO_IRQ	((unsigned int)(-1))
#endif

struct pt_regs;

extern void migrate_irqs(void);
extern void set_handle_irq(void (*handle_irq)(struct pt_regs *));
extern irq_hw_number_t virq_to_hw(unsigned int virq);

static inline void acpi_irq_init(void)
{
	/*
	 * Hardcode ACPI IRQ chip initialization to GICv2 for now.
	 * Proper irqchip infrastructure will be implemented along with
	 * incoming  GICv2m|GICv3|ITS bits.
	 */
	acpi_gic_init();
}
#define acpi_irq_init acpi_irq_init

#endif
