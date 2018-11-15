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
	struct epoch_context	 pfil_epoch_ctx;
};

static int pfil_chain_add(pfil_chain_t *, struct pfil_hook *, int);
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
		rv = (*pfh->pfil_func)(&m, ifp, flags, inp);
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

/*
 * pfil_head_get() returns the pfil_head for a given name.
 */
struct pfil_head *
pfil_head_get(const char *name)
{
	struct pfil_head *ph;

	PFIL_LOCK();
	LIST_FOREACH(ph, &V_pfil_head_list, ph_list)
		if (strcmp(name, ph->ph_name) == 0)
			break;
	PFIL_UNLOCK();

	return (ph);
}

/*
 * pfil_add_hook() adds a function to the packet filter hook.  the
 * flags are:
 *	PFIL_IN		call me on incoming packets
 *	PFIL_OUT	call me on outgoing packets
 */
int
pfil_add_hook(pfil_func_t func, int flags, struct pfil_head *ph)
{
	struct pfil_hook *pfh1 = NULL;
	struct pfil_hook *pfh2 = NULL;
	struct pfil_hook *old = NULL;
	int err;

	MPASS(func);

	if (flags & PFIL_IN)
		pfh1 = malloc(sizeof(*pfh1), M_PFIL, M_WAITOK);
	if (flags & PFIL_OUT)
		pfh2 = malloc(sizeof(*pfh1), M_PFIL, M_WAITOK);
	PFIL_LOCK();
	if (flags & PFIL_IN) {
		pfh1->pfil_func = func;
		err = pfil_chain_add(&ph->ph_in, pfh1, flags & ~PFIL_OUT);
		if (err)
			goto locked_error;
		ph->ph_nhooksin++;
	}
	if (flags & PFIL_OUT) {
		pfh2->pfil_func = func;
		err = pfil_chain_add(&ph->ph_out, pfh2, flags & ~PFIL_IN);
		if (err) {
			if (flags & PFIL_IN)
				old = pfil_chain_remove(&ph->ph_in, func);
			goto locked_error;
		}
		ph->ph_nhooksout++;
	}
	PFIL_UNLOCK();

	return (0);

locked_error:
	PFIL_UNLOCK();
	if (pfh1 != NULL)
		free(pfh1, M_PFIL);
	if (pfh2 != NULL)
		free(pfh2, M_PFIL);
	if (old != NULL)
		epoch_call(PFIL_EPOCH, &old->pfil_epoch_ctx, pfil_chain_free);
	return (err);
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
pfil_remove_hook(pfil_func_t func, int flags, struct pfil_head *ph)
{
	struct pfil_hook *in, *out;

	PFIL_LOCK();
	if (flags & PFIL_IN) {
		in = pfil_chain_remove(&ph->ph_in, func);
		if (in != NULL)
			ph->ph_nhooksin--;
	} else
		in = NULL;
	if (flags & PFIL_OUT) {
		out = pfil_chain_remove(&ph->ph_out, func);
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
 * Internal: Add a new pfil hook into a hook chain.
 */
static int
pfil_chain_add(pfil_chain_t *chain, struct pfil_hook *pfh1, int flags)
{
	struct pfil_hook *pfh;

	PFIL_LOCK_ASSERT();

	/*
	 * First make sure the hook is not already there.
	 */
	CK_STAILQ_FOREACH(pfh, chain, pfil_chain)
		if (pfh->pfil_func == pfh1->pfil_func)
			return (EEXIST);

	/*
	 * Insert the input list in reverse order of the output list so that
	 * the same path is followed in or out of the kernel.
	 */
	if (flags & PFIL_IN)
		CK_STAILQ_INSERT_HEAD(chain, pfh1, pfil_chain);
	else
		CK_STAILQ_INSERT_TAIL(chain, pfh1, pfil_chain);

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
static int
pfil_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	int error;

	error = 0;
	switch (cmd) {
	case PFILIOC_LISTHEADS: {
		struct pfilioc_listheads *req = (struct pfilioc_listheads *)addr;
		struct pfilioc_head ioch;
		struct pfil_head *ph;
		int nheads;

		nheads = 0;
		PFIL_LOCK();
		LIST_FOREACH(ph, &V_pfil_head_list, ph_list) {
			if (++nheads > req->plh_nheads)
				continue;
			bcopy(ph->ph_name, ioch.ph_name, sizeof(ioch.ph_name));
			ioch.ph_nhooksin = ph->ph_nhooksin;
			ioch.ph_nhooksout = ph->ph_nhooksout;
			ioch.ph_type = ph->ph_type;
			error = copyout(&ioch, &req->plh_heads[nheads - 1],
			    sizeof(ioch));
			if (error != 0)
				break;
		}
		PFIL_UNLOCK();
		req->plh_nheads = nheads;

		break;
	}
	default:
		return (EINVAL);
	}

	return (error);
}
