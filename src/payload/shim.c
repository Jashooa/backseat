/* shim for the backseat payload:
 *   - siglongjmp wrapper (macro -> symbol)
 *   - dl_iterate_phdr wrapper for GOT patching
 *
 * __sigsetjmp is called directly from Rust (it IS a real glibc symbol).
 */

#define _GNU_SOURCE
#include <setjmp.h>
#include <link.h>
#include <stddef.h>
#include <string.h>
#include <elf.h>

void sj_longjmp(sigjmp_buf *buf, int val)
{
    siglongjmp(*buf, val);
}

/* ------------------------------------------------------------------ */
/* dl_iterate_phdr — Rust callback per loaded module                  */
/* ------------------------------------------------------------------ */

/* External Rust function — defined in lib.rs.
   Called per loaded module to patch GOT entries for `symbol` -> `hook`.
   Returns 0 to continue iterating, non-zero to stop. */
extern int rust_patch_got_for_module(
    uintptr_t base,
    const Elf64_Phdr *phdr,
    uint16_t phnum,
    const char *symbol,
    void *hook
);

struct dl_callback_data {
    const char *symbol;
    void *hook;
};

static int dl_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    struct dl_callback_data *d = (struct dl_callback_data *)data;

    /* Skip empty-name entries. */
    if (!info->dlpi_name || info->dlpi_name[0] == '\0')
        return 0;
    /* Skip the dynamic linker — self-relocated, .dynamic = absolute. */
    if (strstr(info->dlpi_name, "ld-linux") || strstr(info->dlpi_name, "/ld-"))
        return 0;

    return rust_patch_got_for_module(
        (uintptr_t)info->dlpi_addr,
        info->dlpi_phdr,
        info->dlpi_phnum,
        d->symbol,
        d->hook
    );
}

void patch_gots_via_phdrs(const char *symbol, void *hook)
{
    struct dl_callback_data data = { symbol, hook };
    dl_iterate_phdr(dl_callback, &data);
}
