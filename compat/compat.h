#ifndef COMPAT_H
#define COMPAT_H

#ifndef HAVE_PLEDGE
#include "pledge.h"
#endif

/* Use CLOCK_REALTIME if CLOCK_MONOTONIC is not available */
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC CLOCK_REALTIME
#endif

#endif /* COMPAT_H */
