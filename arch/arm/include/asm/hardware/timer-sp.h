struct clk;

void __sp804_clocksource_and_sched_clock_init(void __iomem *,
					      unsigned long,
					      const char *, struct clk *, int);
void __sp804_clockevents_init(void __iomem *, unsigned int,
			      struct clk *, const char *);

static inline void sp804_clocksource_init(void __iomem *base, 
					  unsigned long phys, const char *name)
{
	__sp804_clocksource_and_sched_clock_init(base, phys, name, NULL, 0);
}

static inline void sp804_clocksource_and_sched_clock_init(void __iomem *base,
							  unsigned long phys,
							  const char *name)
{
	__sp804_clocksource_and_sched_clock_init(base, phys, name, NULL, 1);
}

static inline void sp804_clockevents_init(void __iomem *base, unsigned int irq, const char *name)
{
	__sp804_clockevents_init(base, irq, NULL, name);

}
