/*	$FreeBSD$ */
/*	$NetBSD: pfil.h,v 1.22 2003/06/23 12:57:08 martin Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1996 Matthew R. Green
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
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NET_PFIL_H_
#define _NET_PFIL_H_

#include <sys/ioccom.h>

enum pfil_types {
	PFIL_TYPE_IP4,
	PFIL_TYPE_IP6,
	PFIL_TYPE_ETHERNET,
};

struct pfilioc_head {
	char		ph_name[IFNAMSIZ];
	int		ph_nhooksin;
	int		ph_nhooksout;
	enum pfil_types	ph_type;
};

struct pfilioc_listheads {
	int			 plh_nheads;
	struct pfilioc_head	*plh_heads;
};

#define	PFILDEV			"pfil"
#define	PFILIOC_LISTHEADS	_IOWR('P', 1, struct pfilioc_listheads)

#ifdef _KERNEL
#include <sys/ck.h>

struct mbuf;
struct ifnet;
struct inpcb;

typedef	int	(*pfil_func_t)(struct mbuf **, struct ifnet *, int,
		    struct inpcb *);

#define PFIL_IN		0x00000001
#define PFIL_OUT	0x00000002
#define PFIL_FWD	0x00000008
#define PFIL_DIR(f)	((f) & (PFIL_IN|PFIL_OUT))

/*
 * A pfil head is created by each protocol or packet intercept point.
 * For packet is then run through the hook chain for inspection.
 */
struct pfil_hook;
typedef CK_STAILQ_HEAD(pfil_chain, pfil_hook)	pfil_chain_t;
struct pfil_head {
	pfil_chain_t	 ph_in;
	pfil_chain_t	 ph_out;
	int		 ph_nhooksin;
	int		 ph_nhooksout;
	int		 ph_flags;
	enum pfil_types	 ph_type;
	LIST_ENTRY(pfil_head) ph_list;
	char		ph_name[IFNAMSIZ];
};

/* Public functions for pfil hook management by packet filters. */
struct pfil_head *pfil_head_get(const char *name);
int	pfil_add_hook(pfil_func_t, int, struct pfil_head *);
int	pfil_remove_hook(pfil_func_t, int, struct pfil_head *);

/* Public functions to run the packet inspection by protocols. */
int	pfil_run_hooks(struct pfil_head *, struct mbuf **, struct ifnet *, int,
    struct inpcb *inp);
#define	PFIL_HOOKED_IN(p) ((p)->ph_nhooksin > 0)
#define	PFIL_HOOKED_OUT(p) ((p)->ph_nhooksout > 0)

/* Public functions for pfil head management by protocols. */
int	pfil_head_register(struct pfil_head *);
int	pfil_head_unregister(struct pfil_head *);

#endif /* _KERNEL */
#endif /* _NET_PFIL_H_ */
