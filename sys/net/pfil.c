/*	$FreeBSD$ */
/*	$NetBSD: pfil.c,v 1.20 2001/11/12 23:49:46 lukem Exp $	*/

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

#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/epoch.h>
#include <sys/errno.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/pfil.h>

static MALLOC_DEFINE(M_PFIL, "pfil", "pfil(9) packet filter hooks");

static int pfil_ioctl(struct cdev *, u_long, caddr_t, int, struct thread *);
static struct cdevsw pfil_cdevsw = {
	.d_ioctl =	pfil_ioctl,
	.d_name =	PFILDEV,
	.d_version =	D_VERSION,
};
static struct cdev *pfil_dev;

static struct mtx pfil_lock;
MTX_SYSINIT(pfil_mtxinit, &pfil_lock, "pfil(9) lock", MTX_DEF);
#define	PFIL_LOCK()	mtx_lock(&pfil_lock)
#define	PFIL_UNLOCK()	mtx_unlock(&pfil_lock)
#define	PFIL_LOCK_ASSERT()	mtx_assert(&pfil_lock, MA_OWNED)

LIST_HEAD(pfilheadhead, pfil_head);
VNET_DEFINE_STATIC(struct pfilheadhead, pfil_head_list);
#define	V_pfil_head_list	VNET(pfil_head_list)

#define	PFIL_EPOCH		net_epoch_preempt
#define	PFIL_EPOCH_ENTER(et)	epoch_enter_preempt(net_epoch_preempt, &(et))
#define	PFIL_EPOCH_EXIT(et)	epoch_exit_preempt(net_epoch_preempt, &(et))

struct pfil_hook {
	CK_STAILQ_ENTRY(pfil_hook) pfil_chain;
	pfil_func_t		 pfil_func;
	void			*pfil_ruleset;
	struct epoch_context	 pfil_epoch_ctx;
	const char		*pfil_modname;
	const char		*pfil_rulname;
};

static struct pfil_hook *pfil_chain_remove(pfil_chain_t *, pfil_func_t );
static void pfil_chain_free(epoch_context_t);

/*
 * pfil_run_hooks() runs the specified packet filter hook chain.
 */
int
pfil_run_hooks(struct pfil_head *ph, struct mbuf **mp, struct ifnet *ifp,
    int flags, struct inpcb *inp)
{
	struct epoch_tracker et;
	pfil_chain_t *pch;
	struct pfil_hook *pfh;
	struct mbuf *m = *mp;
	int rv = 0;

	if (PFIL_DIR(flags) == PFIL_IN)
		pch = &ph->ph_in;
	else if (__predict_true(PFIL_DIR(flags) == PFIL_OUT))
		pch = &ph->ph_out;
	else
		panic("%s: bogus flags %d", __func__, flags);

	PFIL_EPOCH_ENTER(et);
	CK_STAILQ_FOREACH(pfh, pch, pfil_chain) {
		rv = (*pfh->pfil_func)(&m, ifp, flags, pfh->pfil_ruleset, inp);
		if (rv != 0 || m == NULL)
			break;
	}
	PFIL_EPOCH_EXIT(et);
	*mp = m;
	return (rv);
}

/*
 * pfil_head_register() registers a pfil_head with the packet filter hook
 * mechanism.
 */
int
pfil_head_register(struct pfil_head *ph)
{
	struct pfil_head *lph;

	PFIL_LOCK();
	LIST_FOREACH(lph, &V_pfil_head_list, ph_list) {
		if (strcmp(ph->ph_name, lph->ph_name) == 0) {
			PFIL_UNLOCK();
			return (EEXIST);
		}
	}
	ph->ph_nhooksin = ph->ph_nhooksout = 0;
	CK_STAILQ_INIT(&ph->ph_in);
	CK_STAILQ_INIT(&ph->ph_out);
	LIST_INSERT_HEAD(&V_pfil_head_list, ph, ph_list);
	PFIL_UNLOCK();

	return (0);
}

/*
 * pfil_head_unregister() removes a pfil_head from the packet filter hook
 * mechanism.  The producer of the hook promises that all outstanding
 * invocations of the hook have completed before it unregisters the hook.
 */
int
pfil_head_unregister(struct pfil_head *ph)
{
	struct pfil_hook *pfh, *pfnext;
		
	PFIL_LOCK();
	LIST_REMOVE(ph, ph_list);
	PFIL_UNLOCK();

	CK_STAILQ_FOREACH_SAFE(pfh, &ph->ph_in, pfil_chain, pfnext)
		free(pfh, M_PFIL);
	CK_STAILQ_FOREACH_SAFE(pfh, &ph->ph_out, pfil_chain, pfnext)
		free(pfh, M_PFIL);

	return (0);
}

int
pfil_add_hook(struct pfil_args *pa)
{
	struct pfil_head *ph;
	struct pfil_hook *in, *out;
	int error;

	MPASS(pa->pa_version == PFIL_VERSION);

	if (pa->pa_flags & PFIL_IN) {
		in = malloc(sizeof(*in), M_PFIL, M_WAITOK | M_ZERO);
		in->pfil_func = pa->pa_func;
		in->pfil_ruleset= pa->pa_ruleset;
		in->pfil_modname = pa->pa_modname;
		if (pa->pa_rulname != NULL)
			in->pfil_rulname = pa->pa_rulname;
		else
			in->pfil_rulname = "-";
	} else
		in = NULL;
	if (pa->pa_flags & PFIL_OUT) {
		out = malloc(sizeof(*out), M_PFIL, M_WAITOK | M_ZERO);
		out->pfil_func = pa->pa_func;
		out->pfil_ruleset= pa->pa_ruleset;
		out->pfil_modname = pa->pa_modname;
		if (pa->pa_rulname != NULL)
			out->pfil_rulname = pa->pa_rulname;
		else
			out->pfil_rulname = "-";
	} else
		out = NULL;

	PFIL_LOCK();
	LIST_FOREACH(ph, &V_pfil_head_list, ph_list)
		if (strcmp(pa->pa_headname, ph->ph_name) == 0)
			break;

	if (ph == NULL) {
		error = ENOENT;
		goto fail;
	}

	if (ph->ph_type != pa->pa_type || (pa->pa_flags & ~ph->ph_flags)) {
		error = EINVAL;
		goto fail;
	}

	if (pa->pa_flags & PFIL_IN) {
		CK_STAILQ_INSERT_HEAD(&ph->ph_in, in, pfil_chain);
		ph->ph_nhooksin++;
	}
	if (pa->pa_flags & PFIL_OUT) {
		CK_STAILQ_INSERT_TAIL(&ph->ph_out, out, pfil_chain);
		ph->ph_nhooksout++;
	}
	PFIL_UNLOCK();

	return (0);

fail:
	PFIL_UNLOCK();
	free(in, M_PFIL);
	free(out, M_PFIL);
	return (error);
}

static void
pfil_chain_free(epoch_context_t ctx)
{
	struct pfil_hook *pfh;

	pfh = __containerof(ctx, struct pfil_hook, pfil_epoch_ctx);
	free(pfh, M_PFIL);
}

/*
 * pfil_remove_hook removes a specific function from the packet filter hook
 * chain.
 */
int
pfil_remove_hook(struct pfil_args *pa)
{
	struct pfil_head *ph;
	struct pfil_hook *in, *out;

	PFIL_LOCK();
	LIST_FOREACH(ph, &V_pfil_head_list, ph_list)
		if (strcmp(pa->pa_headname, ph->ph_name) == 0)
			break;

	if (ph == NULL) {
		PFIL_UNLOCK();
		return (ENOENT);
	}

	if (pa->pa_flags & PFIL_IN) {
		in = pfil_chain_remove(&ph->ph_in, pa->pa_func);
		if (in != NULL)
			ph->ph_nhooksin--;
	} else
		in = NULL;
	if (pa->pa_flags & PFIL_OUT) {
		out = pfil_chain_remove(&ph->ph_out, pa->pa_func);
		if (out != NULL)
			ph->ph_nhooksout--;
	} else
		out = NULL;
	PFIL_UNLOCK();

	if (in != NULL)
		epoch_call(PFIL_EPOCH, &in->pfil_epoch_ctx, pfil_chain_free);
	if (out != NULL)
		epoch_call(PFIL_EPOCH, &out->pfil_epoch_ctx, pfil_chain_free);

	return (0);
}

/*
 * Internal: Remove a pfil hook from a hook chain.
 */
static struct pfil_hook *
pfil_chain_remove(pfil_chain_t *chain, pfil_func_t func)
{
	struct pfil_hook *pfh;

	PFIL_LOCK_ASSERT();

	CK_STAILQ_FOREACH(pfh, chain, pfil_chain)
		if (pfh->pfil_func == func) {
			CK_STAILQ_REMOVE(chain, pfh, pfil_hook,
			    pfil_chain);
			return (pfh);
		}

	return (NULL);
}

/*
 * Stuff that must be initialized for every instance (including the first of
 * course).
 */
static void
vnet_pfil_init(const void *unused __unused)
{
	struct make_dev_args args;
	int error;

	LIST_INIT(&V_pfil_head_list);

	make_dev_args_init(&args);
	args.mda_flags = MAKEDEV_WAITOK | MAKEDEV_CHECKNAME;
	args.mda_devsw = &pfil_cdevsw;
	args.mda_uid = UID_ROOT;
	args.mda_gid = GID_WHEEL;
	args.mda_mode = 0600;
	error = make_dev_s(&args, &pfil_dev, PFILDEV);
	KASSERT(error == 0, ("%s: failed to create dev: %d", __func__, error));
}
/*
 * Make sure the pfil bits are first before any possible subsystem which
 * might piggyback on the SI_SUB_PROTO_PFIL.
 */
VNET_SYSINIT(vnet_pfil_init, SI_SUB_PROTO_PFIL, SI_ORDER_FIRST,
    vnet_pfil_init, NULL);

#ifdef INVARIANTS
/*
 * Called for the removal of each instance.
 */
static void
vnet_pfil_uninit(const void *unused __unused)
{

	KASSERT(LIST_EMPTY(&V_pfil_head_list),
	    ("%s: pfil_head_list %p not empty", __func__, &V_pfil_head_list));
}
VNET_SYSUNINIT(vnet_pfil_uninit, SI_SUB_PROTO_PFIL, SI_ORDER_FIRST,
    vnet_pfil_uninit, NULL);
#endif

/*
 * User control interface.
 */
static int pfilioc_listheads(struct pfilioc_listheads *);

static int
pfil_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	int error;

	error = 0;
	switch (cmd) {
	case PFILIOC_LISTHEADS:
		error = pfilioc_listheads((struct pfilioc_listheads *)addr);
		break;
	default:
		return (EINVAL);
	}

	return (error);
}

static int
pfilioc_listheads(struct pfilioc_listheads *req)
{
	struct pfil_head *ph;
	struct pfilioc_head *iohead;
	struct pfilioc_hook *iohook;
	struct pfil_hook *pfh;
	u_int nheads, nhooks, hd, hk;
	int error;

	PFIL_LOCK();
restart:
	nheads = nhooks = 0;
	LIST_FOREACH(ph, &V_pfil_head_list, ph_list) {
		nheads++;
		nhooks += ph->ph_nhooksin + ph->ph_nhooksout;
	}
	PFIL_UNLOCK();

	if (req->plh_nheads < nheads || req->plh_nhooks < nhooks) {
		req->plh_nheads = nheads;
		req->plh_nhooks = nhooks;
		return (0);
	}

	iohead = malloc(sizeof(*iohead) * nheads, M_TEMP, M_WAITOK);
	iohook = malloc(sizeof(*iohook) * nhooks, M_TEMP, M_WAITOK);

	hd = hk = 0;
	PFIL_LOCK();
	LIST_FOREACH(ph, &V_pfil_head_list, ph_list) {
		if (hd + 1 > nheads ||
		    hk + ph->ph_nhooksin + ph->ph_nhooksout > nhooks) {
			/* Configuration changed during malloc(). */
			free(iohead, M_TEMP);
			free(iohook, M_TEMP);
			goto restart;
		}
		strlcpy(iohead[hd].ph_name, ph->ph_name,
			sizeof(iohead[0].ph_name));
		iohead[hd].ph_nhooksin = ph->ph_nhooksin;
		iohead[hd].ph_nhooksout = ph->ph_nhooksout;
		iohead[hd].ph_type = ph->ph_type;
		CK_STAILQ_FOREACH(pfh, &ph->ph_in, pfil_chain) {
			strlcpy(iohook[hk].ph_module, pfh->pfil_modname,
			    sizeof(iohook[0].ph_module));
			strlcpy(iohook[hk].ph_ruleset, pfh->pfil_rulname,
			    sizeof(iohook[0].ph_ruleset));
			hk++;
		}
		CK_STAILQ_FOREACH(pfh, &ph->ph_out, pfil_chain) {
			strlcpy(iohook[hk].ph_module, pfh->pfil_modname,
			    sizeof(iohook[0].ph_module));
			strlcpy(iohook[hk].ph_ruleset, pfh->pfil_rulname,
			    sizeof(iohook[0].ph_ruleset));
			hk++;
		}
		hd++;
	}
	PFIL_UNLOCK();

	error = copyout(iohead, req->plh_heads,
	    sizeof(*iohead) * min(hd, req->plh_nheads));
	if (error == 0)
		error = copyout(iohook, req->plh_hooks,
		    sizeof(*iohook) * min(req->plh_nhooks, hk));

	req->plh_nheads = hd;
	req->plh_nhooks = hk;

	free(iohead, M_TEMP);
	free(iohook, M_TEMP);

	return (error);
}
