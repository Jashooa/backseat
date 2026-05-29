/* siglongjmp shim for the backseat payload.
 *
 * siglongjmp is typically a macro, not a linkable symbol,
 * so we can't FFI it directly from Rust.  This file exposes a thin
 * wrapper that the payload can call.
 *
 * __sigsetjmp is called directly from Rust (it IS a real glibc symbol),
 * so it doesn't need a wrapper here.
 */

#include <setjmp.h>

void sj_longjmp(sigjmp_buf *buf, int val)
{
    siglongjmp(*buf, val);
}
