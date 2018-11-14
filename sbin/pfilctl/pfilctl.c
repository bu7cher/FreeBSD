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
	struct pfilioc_listheads plh;

	plh.plh_nheads = 0;
	if (ioctl(dev, PFILIOC_LISTHEADS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHEADS)");

	plh.plh_heads = calloc(plh.plh_nheads, sizeof(struct pfilioc_head));
	if (plh.plh_heads == NULL)
		err(1, "malloc");

	if (ioctl(dev, PFILIOC_LISTHEADS, &plh) != 0)
		err(1, "ioctl(PFILIOC_LISTHEADS)");

#define	FMT0	"%16s %8s %3s %3s\n"
#define	FMT	"%16s %8s %3u %3u\n"
	printf(FMT0, "Name", "Type", "In", "Out");
	for (int i = 0; i < plh.plh_nheads; i++)
		printf(FMT, plh.plh_heads[i].ph_name,
		    typenames[plh.plh_heads[i].ph_type],
		    plh.plh_heads[i].ph_nhooksin,
		    plh.plh_heads[i].ph_nhooksout);
}

int
main(int argc __unused, char *argv[] __unused)
{

	dev = open("/dev/" PFILDEV, O_RDWR);
	if (dev == -1)
		err(1, "open(%s)", "/dev/" PFILDEV);

	listheads();

	return (0);
}
