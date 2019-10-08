#define __COBALT_CALL_ENTRIES \
	__COBALT_CALL_ENTRY(migrate) \
	__COBALT_CALL_ENTRY(trace) \
	__COBALT_CALL_ENTRY(ftrace_puts) \
	__COBALT_CALL_ENTRY(archcall) \
	__COBALT_CALL_ENTRY(get_current) \
	__COBALT_CALL_ENTRY(backtrace) \
	__COBALT_CALL_ENTRY(serialdbg) \
	__COBALT_CALL_ENTRY(bind) \
	__COBALT_CALL_ENTRY(extend) \
	__COBALT_CALL_ENTRY(timerfd_create) \
	__COBALT_CALL_ENTRY(timerfd_settime) \
	__COBALT_CALL_ENTRY(timerfd_gettime) \
	__COBALT_CALL_ENTRY(monitor_init) \
	__COBALT_CALL_ENTRY(monitor_enter) \
	__COBALT_CALL_ENTRY(monitor_wait) \
	__COBALT_CALL_ENTRY(monitor_sync) \
	__COBALT_CALL_ENTRY(monitor_exit) \
	__COBALT_CALL_ENTRY(monitor_destroy) \
	__COBALT_CALL_ENTRY(open) \
	__COBALT_CALL_ENTRY(socket) \
	__COBALT_CALL_ENTRY(close) \
	__COBALT_CALL_ENTRY(fcntl) \
	__COBALT_CALL_ENTRY(ioctl) \
	__COBALT_CALL_ENTRY(read) \
	__COBALT_CALL_ENTRY(write) \
	__COBALT_CALL_ENTRY(recvmsg) \
	__COBALT_CALL_ENTRY(recvmmsg) \
	__COBALT_CALL_ENTRY(sendmsg) \
	__COBALT_CALL_ENTRY(sendmmsg) \
	__COBALT_CALL_ENTRY(mmap) \
	__COBALT_CALL_ENTRY(select) \
	__COBALT_CALL_ENTRY(clock_getres) \
	__COBALT_CALL_ENTRY(clock_gettime) \
	__COBALT_CALL_ENTRY(clock_settime) \
	__COBALT_CALL_ENTRY(clock_adjtime) \
	__COBALT_CALL_ENTRY(clock_nanosleep) \
	__COBALT_CALL_ENTRY(sem_init) \
	__COBALT_CALL_ENTRY(sem_post) \
	__COBALT_CALL_ENTRY(sem_wait) \
	__COBALT_CALL_ENTRY(sem_timedwait) \
	__COBALT_CALL_ENTRY(sem_trywait) \
	__COBALT_CALL_ENTRY(sem_getvalue) \
	__COBALT_CALL_ENTRY(sem_destroy) \
	__COBALT_CALL_ENTRY(sem_broadcast_np) \
	__COBALT_CALL_ENTRY(sem_inquire) \
	__COBALT_CALL_ENTRY(mutex_check_init) \
	__COBALT_CALL_ENTRY(mutex_init) \
	__COBALT_CALL_ENTRY(mutex_destroy) \
	__COBALT_CALL_ENTRY(mutex_trylock) \
	__COBALT_CALL_ENTRY(mutex_lock) \
	__COBALT_CALL_ENTRY(mutex_timedlock) \
	__COBALT_CALL_ENTRY(mutex_unlock) \
	__COBALT_CALL_ENTRY(sched_minprio) \
	__COBALT_CALL_ENTRY(sched_maxprio) \
	__COBALT_CALL_ENTRY(sched_yield) \
	__COBALT_CALL_ENTRY(sched_setconfig_np) \
	__COBALT_CALL_ENTRY(sched_getconfig_np) \
	__COBALT_CALL_ENTRY(sched_weightprio) \
	__COBALT_CALL_ENTRY(sched_setscheduler_ex) \
	__COBALT_CALL_ENTRY(sched_getscheduler_ex) \
	__COBALT_CALL_ENTRY(event_init) \
	__COBALT_CALL_ENTRY(event_wait) \
	__COBALT_CALL_ENTRY(event_sync) \
	__COBALT_CALL_ENTRY(event_destroy) \
	__COBALT_CALL_ENTRY(event_inquire) \
	__COBALT_CALL_ENTRY(sigwait) \
	__COBALT_CALL_ENTRY(sigtimedwait) \
	__COBALT_CALL_ENTRY(sigwaitinfo) \
	__COBALT_CALL_ENTRY(sigpending) \
	__COBALT_CALL_ENTRY(kill) \
	__COBALT_CALL_ENTRY(sigqueue) \
	__COBALT_CALL_ENTRY(mq_notify) \
	__COBALT_CALL_ENTRY(mq_open) \
	__COBALT_CALL_ENTRY(mq_close) \
	__COBALT_CALL_ENTRY(mq_unlink) \
	__COBALT_CALL_ENTRY(mq_getattr) \
	__COBALT_CALL_ENTRY(mq_timedsend) \
	__COBALT_CALL_ENTRY(mq_timedreceive) \
	__COBALT_CALL_ENTRY(corectl) \
	__COBALT_CALL_ENTRY(cond_init) \
	__COBALT_CALL_ENTRY(cond_destroy) \
	__COBALT_CALL_ENTRY(cond_wait_prologue) \
	__COBALT_CALL_ENTRY(cond_wait_epilogue) \
	__COBALT_CALL_ENTRY(sem_open) \
	__COBALT_CALL_ENTRY(sem_close) \
	__COBALT_CALL_ENTRY(sem_unlink) \
	__COBALT_CALL_ENTRY(thread_setschedparam_ex) \
	__COBALT_CALL_ENTRY(thread_getschedparam_ex) \
	__COBALT_CALL_ENTRY(thread_create) \
	__COBALT_CALL_ENTRY(thread_setmode) \
	__COBALT_CALL_ENTRY(thread_setname) \
	__COBALT_CALL_ENTRY(thread_kill) \
	__COBALT_CALL_ENTRY(thread_join) \
	__COBALT_CALL_ENTRY(thread_getpid) \
	__COBALT_CALL_ENTRY(thread_getstat) \
	__COBALT_CALL_ENTRY(timer_delete) \
	__COBALT_CALL_ENTRY(timer_create) \
	__COBALT_CALL_ENTRY(timer_settime) \
	__COBALT_CALL_ENTRY(timer_gettime) \
	__COBALT_CALL_ENTRY(timer_getoverrun) \
	/* end */
#define __COBALT_CALL_MODES \
	__COBALT_MODE(migrate, current) \
	__COBALT_MODE(trace, current) \
	__COBALT_MODE(ftrace_puts, current) \
	__COBALT_MODE(archcall, current) \
	__COBALT_MODE(get_current, current) \
	__COBALT_MODE(backtrace, lostage) \
	__COBALT_MODE(serialdbg, current) \
	__COBALT_MODE(bind, lostage) \
	__COBALT_MODE(extend, lostage) \
	__COBALT_MODE(timerfd_create, lostage) \
	__COBALT_MODE(timerfd_settime, primary) \
	__COBALT_MODE(timerfd_gettime, current) \
	__COBALT_MODE(monitor_init, current) \
	__COBALT_MODE(monitor_enter, primary) \
	__COBALT_MODE(monitor_wait, nonrestartable) \
	__COBALT_MODE(monitor_sync, nonrestartable) \
	__COBALT_MODE(monitor_exit, primary) \
	__COBALT_MODE(monitor_destroy, primary) \
	__COBALT_MODE(open, lostage) \
	__COBALT_MODE(socket, lostage) \
	__COBALT_MODE(close, lostage) \
	__COBALT_MODE(fcntl, current) \
	__COBALT_MODE(ioctl, handover) \
	__COBALT_MODE(read, handover) \
	__COBALT_MODE(write, handover) \
	__COBALT_MODE(recvmsg, handover) \
	__COBALT_MODE(recvmmsg, primary) \
	__COBALT_MODE(sendmsg, handover) \
	__COBALT_MODE(sendmmsg, primary) \
	__COBALT_MODE(mmap, lostage) \
	__COBALT_MODE(select, primary) \
	__COBALT_MODE(clock_getres, current) \
	__COBALT_MODE(clock_gettime, current) \
	__COBALT_MODE(clock_settime, current) \
	__COBALT_MODE(clock_adjtime, current) \
	__COBALT_MODE(clock_nanosleep, primary) \
	__COBALT_MODE(sem_init, current) \
	__COBALT_MODE(sem_post, current) \
	__COBALT_MODE(sem_wait, primary) \
	__COBALT_MODE(sem_timedwait, primary) \
	__COBALT_MODE(sem_trywait, primary) \
	__COBALT_MODE(sem_getvalue, current) \
	__COBALT_MODE(sem_destroy, current) \
	__COBALT_MODE(sem_broadcast_np, current) \
	__COBALT_MODE(sem_inquire, current) \
	__COBALT_MODE(mutex_check_init, current) \
	__COBALT_MODE(mutex_init, current) \
	__COBALT_MODE(mutex_destroy, current) \
	__COBALT_MODE(mutex_trylock, primary) \
	__COBALT_MODE(mutex_lock, primary) \
	__COBALT_MODE(mutex_timedlock, primary) \
	__COBALT_MODE(mutex_unlock, nonrestartable) \
	__COBALT_MODE(sched_minprio, current) \
	__COBALT_MODE(sched_maxprio, current) \
	__COBALT_MODE(sched_yield, primary) \
	__COBALT_MODE(sched_setconfig_np, conforming) \
	__COBALT_MODE(sched_getconfig_np, conforming) \
	__COBALT_MODE(sched_weightprio, current) \
	__COBALT_MODE(sched_setscheduler_ex, conforming) \
	__COBALT_MODE(sched_getscheduler_ex, current) \
	__COBALT_MODE(event_init, current) \
	__COBALT_MODE(event_wait, primary) \
	__COBALT_MODE(event_sync, current) \
	__COBALT_MODE(event_destroy, current) \
	__COBALT_MODE(event_inquire, current) \
	__COBALT_MODE(sigwait, primary) \
	__COBALT_MODE(sigtimedwait, nonrestartable) \
	__COBALT_MODE(sigwaitinfo, nonrestartable) \
	__COBALT_MODE(sigpending, primary) \
	__COBALT_MODE(kill, conforming) \
	__COBALT_MODE(sigqueue, conforming) \
	__COBALT_MODE(mq_notify, primary) \
	__COBALT_MODE(mq_open, lostage) \
	__COBALT_MODE(mq_close, lostage) \
	__COBALT_MODE(mq_unlink, lostage) \
	__COBALT_MODE(mq_getattr, current) \
	__COBALT_MODE(mq_timedsend, primary) \
	__COBALT_MODE(mq_timedreceive, primary) \
	__COBALT_MODE(corectl, probing) \
	__COBALT_MODE(cond_init, current) \
	__COBALT_MODE(cond_destroy, current) \
	__COBALT_MODE(cond_wait_prologue, nonrestartable) \
	__COBALT_MODE(cond_wait_epilogue, primary) \
	__COBALT_MODE(sem_open, lostage) \
	__COBALT_MODE(sem_close, lostage) \
	__COBALT_MODE(sem_unlink, lostage) \
	__COBALT_MODE(thread_setschedparam_ex, conforming) \
	__COBALT_MODE(thread_getschedparam_ex, current) \
	__COBALT_MODE(thread_create, init) \
	__COBALT_MODE(thread_setmode, primary) \
	__COBALT_MODE(thread_setname, current) \
	__COBALT_MODE(thread_kill, conforming) \
	__COBALT_MODE(thread_join, primary) \
	__COBALT_MODE(thread_getpid, current) \
	__COBALT_MODE(thread_getstat, current) \
	__COBALT_MODE(timer_delete, current) \
	__COBALT_MODE(timer_create, current) \
	__COBALT_MODE(timer_settime, primary) \
	__COBALT_MODE(timer_gettime, current) \
	__COBALT_MODE(timer_getoverrun, current) \
	/* end */
