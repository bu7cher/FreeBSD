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
#include <string.h>
#include <unistd.h>

static int dev;

static const char * const typenames[] = {
	[PFIL_TYPE_IP4] = "IPv4",
	[PFIL_TYPE_IP6] = "IPv6",
	[PFIL_TYPE_ETHERNET] = "Ethernet",
};

static void listheads(int argc, char *argv[]);
static void listhooks(int argc, char *argv[]);
static void hook(int argc, char *argv[]);
static void help(void);

static const struct cmd {
	const char	*cmd_name;
	void		(*cmd_func)(int argc, char *argv[]);
} cmds[] = {
	{ "heads",	listheads },
	{ "hooks",	listhooks },
	{ "link",	hook },
	{ "unlink",	hook },
	{ NULL,		NULL },
};

int
main(int argc __unused, char *argv[] __unused)
{
	int cmd = -1;

	if (--argc == 0)
		help();
	argv++;

	for (int i = 0; cmds[i].cmd_name != NULL; i++)
		if (!strncmp(argv[0], cmds[i].cmd_name, strlen(argv[0]))) {
			if (cmd != -1)
				errx(1, "ambiguous command: %s", argv[0]);
			cmd = i;
		}
	if (cmd == -1)
		errx(1, "unknown command: %s", argv[0]);

	dev = open("/dev/" PFILDEV, O_RDWR);
	if (dev == -1)
		err(1, "open(%s)", "/dev/" PFILDEV);

	(*cmds[cmd].cmd_func)(argc, argv);

	return (0);
}

static void 
help(void) 
{
	extern char *__progname;

	fprintf(stderr, "usage: %s (heads|hooks|link|unlink)\n", __progname);
	exit(0);
}

static void
listheads(int argc __unused, char *argv[] __unused)
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
listhooks(int argc __unused, char *argv[] __unused)
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

static void
hook(int argc, char *argv[])
{
	struct pfilioc_link req;
	int c;
	char *ruleset;

	if (argv[0][0] == 'u')
		req.ph_flags = PFIL_UNLINK;
	else
		req.ph_flags = 0;

	while ((c = getopt(argc, argv, "ioa")) != -1)
		switch (c) {
		case 'i':
			req.ph_flags |= PFIL_IN;
			break;
		case 'o':
			req.ph_flags |= PFIL_OUT;
			break;
		case 'a':
			req.ph_flags |= PFIL_APPEND;
			break;
		default:
			help();
		}

	if (!PFIL_DIR(req.ph_flags))
		help();

	argc -= optind;
	argv += optind;

	if (argc != 2)
		help();

	/* link mod:ruleset head */
	if ((ruleset = strchr(argv[0], ':')) == NULL)
		help();
	*ruleset = '\0';
	ruleset++;

	strlcpy(req.ph_name, argv[1], sizeof(req.ph_name));
	strlcpy(req.ph_module, argv[0], sizeof(req.ph_module));
	strlcpy(req.ph_ruleset, ruleset, sizeof(req.ph_ruleset));

	if (ioctl(dev, PFILIOC_LINK, &req) != 0)
		err(1, "ioctl(PFILIOC_LINK)");
}
