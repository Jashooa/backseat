/* sigsetjmp/siglongjmp shim for the backseat payload.
 *
 * sigsetjmp and siglongjmp are typically macros, not linkable symbols,
 * so we can't FFI them directly from Rust.  This file exposes thin
 * wrappers that the payload can call.
 *
 * __sigsetjmp is the glibc implementation (the macro expands to it).
 * On musl the real symbol may differ; adjust if needed.
 */

#include <setjmp.h>
#include <stddef.h>

int sj_setjmp(sigjmp_buf *buf, int savesigs)
{
    return sigsetjmp(*buf, savesigs);
}

void sj_longjmp(sigjmp_buf *buf, int val)
{
    siglongjmp(*buf, val);
}
