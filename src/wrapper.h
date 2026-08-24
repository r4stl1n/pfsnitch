/* libprocstat.h relies on macros and types from these headers but does not
 * include them itself (STAILQ_HEAD from sys/queue.h, struct kinfo_proc from
 * sys/user.h). bindgen therefore needs this wrapper rather than the header
 * directly. */
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <libprocstat.h>
