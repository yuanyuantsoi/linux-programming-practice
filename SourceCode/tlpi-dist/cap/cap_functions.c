/*************************************************************************\
*                  Copyright (C) Michael Kerrisk, 2026.                   *
*                                                                         *
* This program is free software. You may use, modify, and redistribute it *
* under the terms of the GNU Lesser General Public License as published   *
* by the Free Software Foundation, either version 3 or (at your option)   *
* any later version. This program is distributed without any warranty.    *
* See the files COPYING.lgpl-v3 and COPYING.gpl-v3 for details.           *
\*************************************************************************/

/* Supplementary program for Chapter 39 */

/* cap_functions.c

   Useful functions for working with capabilities.
*/

#define _GNU_SOURCE
#include <limits.h>
#include <sys/prctl.h>
#include <linux/securebits.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include "tlpi_hdr.h"
#include "cap_functions.h"

/* Change the 'setting' of the specified 'capability' in the capability set
   specified by 'flag'.

   'flag' is one of CAP_PERMITTED, CAP_EFFECTIVE, or CAP_INHERITABLE.
   'setting' is one of CAP_SET or CAP_CLEAR.

   Returns: 0 on success or -1 on error. */

int
modifyCapSetting(cap_flag_t flag, cap_value_t capability, int setting)
{
    /* Retrieve caller's current capabilities */

    cap_t caps = cap_get_proc();
    if (caps == NULL)
        return -1;

    /* Change setting of 'capability' in the 'flag' capability set in 'caps'.
       The third argument, 1, is the number of items in the array 'capList'. */

    cap_value_t capList[1];
    capList[0] = capability;
    if (cap_set_flag(caps, flag, 1, capList, setting) == -1) {
        cap_free(caps);
        return -1;
    }

    /* Push modified capability sets back to kernel, to change
       caller's capabilities */

    if (cap_set_proc(caps) == -1) {
        cap_free(caps);
        return -1;
    }

    /* Free the structure that was allocated by cap_get_proc() */

    if (cap_free(caps) == -1)
        return -1;

    return 0;
}

/* Display a securebits mask in either short or long form, depending on
   the value of 'verbose'. */

void
printSecbits(int secbits, bool verbose, FILE *fp)
{
    struct secbitInfo {
        int   flag;
        char *name;
        char  letter;
    };

    struct secbitInfo secbitInfoList[] = {
        {SECBIT_NO_CAP_AMBIENT_RAISE,   "NO_CAP_AMBIENT_RAISE",   'a'},
        {SECBIT_NO_CAP_AMBIENT_RAISE_LOCKED,
                                   "NO_CAP_AMBIENT_RAISE_LOCKED", 'A'},
        {SECBIT_KEEP_CAPS,              "KEEP_CAPS",              'k'},
        {SECBIT_KEEP_CAPS_LOCKED,       "KEEP_CAPS_LOCKED",       'K'},
        {SECBIT_NOROOT,                 "NOROOT",                 'r'},
        {SECBIT_NOROOT_LOCKED,          "NOROOT_LOCKED",          'R'},
        {SECBIT_NO_SETUID_FIXUP,        "NO_SETUID_FIXUP",        's'},
        {SECBIT_NO_SETUID_FIXUP_LOCKED, "NO_SETUID_FIXUP_LOCKED", 'S'},
        {0, NULL, '\0'}
    };

    int printed = 0;

    if (verbose) {
        fprintf(fp, "[");
        for (struct secbitInfo *p = secbitInfoList; p->flag != 0; p++) {
            if (secbits & p->flag) {
                if (printed > 0)
                    fprintf(fp, ", ");
                fprintf(fp, "%s", p->name);
                printed++;
            }
        }
        fprintf(fp, "]");
    } else {
        for (struct secbitInfo *p = secbitInfoList; p->flag != 0; p++) {
            if (secbits & p->flag)
                fputc(p->letter, fp);
            else
                fputc('-', fp);
        }
    }
}

void
printCredsAndCaps(FILE *fp, char *leader)
{
    if (leader == NULL)
        leader = "";

    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;

    if (getresuid(&ruid, &euid, &suid) == -1)
        errExit("getresuid");

    if (getresgid(&rgid, &egid, &sgid) == -1)
        errExit("getresgid");

    fprintf(fp, "%srUID: %4ld; eUID: %4ld; sUID: %4ld\n",
            leader, (long) ruid, (long) euid, (long) suid);
    fprintf(fp, "%srGID: %4ld; eGID: %4ld; sGID: %4ld\n",
            leader, (long) rgid, (long) egid, (long) sgid);

    cap_t caps = cap_get_proc();
    if (caps == NULL)
        errExit("cap_get_proc");

    char *s = cap_to_text(caps, NULL);
    if (s == NULL)
        errExit("cap_to_text");

    fprintf(fp, "%sCapabilities: %s\n", leader, s);

    cap_free(caps);
    cap_free(s);
}
