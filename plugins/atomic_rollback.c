#include <rpm/rpmfiles.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmplugin.h>
#include <rpm/rpmte.h>
#include <rpm/rpmts.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BINARY "/usr/bin/atomic-rollback"

/* Writes one record per file of every package the transaction installs,
 * read through rpm's public API: its position in the package's file list,
 * the position of the last file of its hard-link set (its own when it has
 * none), its size, and its path under the transaction's root directory,
 * tab-separated and ended by a NUL byte. */
static void write_package_files(FILE *out, rpmts ts)
{
    const char *root = rpmtsRootDir(ts);
    size_t rootlen = root ? strlen(root) : 0;
    while (rootlen > 0 && root[rootlen - 1] == '/')
        rootlen--;

    rpmtsi pi = rpmtsiInit(ts);
    rpmte te;
    while ((te = rpmtsiNext(pi, TR_ADDED)) != NULL) {
        rpmfiles files = rpmteFiles(te);
        int fc = rpmfilesFC(files);
        for (int i = 0; i < fc; i++) {
            const int *links = NULL;
            uint32_t nlink = rpmfilesFLinks(files, i, &links);
            int last = nlink > 1 ? links[nlink - 1] : i;
            char *fn = rpmfilesFN(files, i);
            fprintf(out, "%d\t%d\t%" PRIu64 "\t%.*s%s", i, last,
                    (uint64_t) rpmfilesFSize(files, i), (int) rootlen,
                    root ? root : "", fn);
            fputc('\0', out);
            free(fn);
        }
        rpmfilesFree(files);
    }
    rpmtsiFree(pi);
}

/* Before the transaction writes anything: atomic-rollback refuses it when
 * its files do not fit beside the snapshot, else takes the snapshot. Its
 * own message says which. */
static rpmRC atomic_rollback_tsm_pre(rpmPlugin plugin, rpmts ts)
{
    if (rpmtsFlags(ts) & (RPMTRANS_FLAG_TEST|RPMTRANS_FLAG_BUILD_PROBS))
        return RPMRC_OK;

    if (access(BINARY, X_OK) != 0)
        return RPMRC_OK;

    FILE *out = popen(BINARY " pre-transaction", "w");
    if (out == NULL) {
        rpmlog(RPMLOG_ERR, "atomic-rollback: cannot run " BINARY ", aborting transaction\n");
        return RPMRC_FAIL;
    }
    write_package_files(out, ts);
    int write_failed = ferror(out);
    int status = pclose(out);
    if (write_failed || status != 0) {
        rpmlog(RPMLOG_ERR, "atomic-rollback: aborting transaction\n");
        return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

struct rpmPluginHooks_s atomic_rollback_hooks = {
    .tsm_pre = atomic_rollback_tsm_pre,
};
