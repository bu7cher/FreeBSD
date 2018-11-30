/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Gleb Smirnoff <glebius@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/pfil.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static const char * const typenames[] = {
	[PFIL_TYPE_IP4] = "IPv4",
	[PFIL_TYPE_IP6] = "IPv6",
	[PFIL_TYPE_ETHERNET] = "Ethernet",
};

static int dev;

static void
listheads(void)
{
	struct pfilioc_list plh;
	u_int nheads, nhooks, i;
	int j, h;

	plh.plh_nheads = 0;
	plh.plh_nhooks = 0;
	if (ioctl(dev, PFILIOC_LISTHEADS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHEADS)");

retry:
	plh.plh_heads = calloc(plh.plh_nheads, sizeof(struct pfilioc_head));
	if (plh.plh_heads == NULL)
		err(1, "malloc");
	plh.plh_hooks = calloc(plh.plh_nhooks, sizeof(struct pfilioc_hook));
	if (plh.plh_hooks == NULL)
		err(1, "malloc");

	nheads = plh.plh_nheads;
	nhooks = plh.plh_nhooks;

	if (ioctl(dev, PFILIOC_LISTHEADS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHEADS)");

	if (plh.plh_nheads > nheads || plh.plh_nhooks > nhooks) {
		free(plh.plh_heads);
		free(plh.plh_hooks);
		goto retry;
	}

#define	FMTHD	"%16s %8s\n"
#define	FMTHK	"%29s %16s %16s\n"
	printf(FMTHD, "Intercept point", "Type");
	for (i = 0, h = 0; i < plh.plh_nheads; i++) {
		printf(FMTHD, plh.plh_heads[i].ph_name,
		    typenames[plh.plh_heads[i].ph_type]);
		for (j = 0; j < plh.plh_heads[i].ph_nhooksin; j++, h++)
			printf(FMTHK, "In", plh.plh_hooks[h].ph_module,
			    plh.plh_hooks[h].ph_ruleset);
		for (j = 0; j < plh.plh_heads[i].ph_nhooksout; j++, h++)
			printf(FMTHK, "Out", plh.plh_hooks[h].ph_module,
			    plh.plh_hooks[h].ph_ruleset);
	}
}

static void
listhooks(void)
{
	struct pfilioc_list plh;
	u_int nhooks, i;

	plh.plh_nhooks = 0;
	if (ioctl(dev, PFILIOC_LISTHEADS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHEADS)");
retry:
	plh.plh_hooks = calloc(plh.plh_nhooks, sizeof(struct pfilioc_hook));
	if (plh.plh_hooks == NULL)
		err(1, "malloc");

	nhooks = plh.plh_nhooks;

	if (ioctl(dev, PFILIOC_LISTHOOKS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHOOKS)");

	if (plh.plh_nhooks > nhooks) {
		free(plh.plh_hooks);
		goto retry;
	}

	printf("Available hooks:\n");
	for (i = 0; i < plh.plh_nhooks; i++) {
		printf("\t%s:%s %s\n", plh.plh_hooks[i].ph_module,
		    plh.plh_hooks[i].ph_ruleset,
		    typenames[plh.plh_hooks[i].ph_type]);
	}
}

int
main(int argc __unused, char *argv[] __unused)
{

	dev = open("/dev/" PFILDEV, O_RDWR);
	if (dev == -1)
		err(1, "open(%s)", "/dev/" PFILDEV);

	listheads();

	listhooks();

	return (0);
}
