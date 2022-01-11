<!-- .slide: data-state="cover-image" id="cover-page-image" data-timing="20" data-menu-title="Cover slide with QR code" -->
<div class="title">
    <h1>Automating Code Review with Sparse</h1>
    <h2>Project specific static analysis <br>of a large C codebase</h2>
</div>

<div class="date-location">FOSDEM 2022</div>


<!-- .slide: data-state="normal" id="what-is-race" data-timing="20s" data-menu-title="What is a data race?" -->
## What is a data race?

<div class="breadcrumbs">Data race</div>

Informally and according to Richard Palethorpe.

* It is also called a race condition.

* It requires a computation which reads at least one variable from
  somewhere.

* The result(s) of the computation must change depending on the value
  of the variable.

* The value of the variable must change over time. Thus the result of
  the computation changes over time.

* Only static, purely functional code has no data races.

### However...

Usually if someone talks about a "data race" or "race condition" they
are talking about a bug caused by a data race.


<!-- .slide: data-state="normal" id="what-is-kernel-race" data-timing="20s" data-menu-title="Typical kernel races" -->
## What do kernel data races typically look like?

<div class="breadcrumbs">Kernel race</div>

A gross and degenerate simplification.

* A block of code updates a memory pointer (Block A).

* Another block reads a memory pointer (Block B).

* The blocks may run concurrently.

* Block A should only run after/before B to ensure the pointer value
  is valid for B.

* The ordering of memory accesses has not been ensured in all
  scenarios.

* Block B blows up when it dereferences a dodgy pointer.

### However...

* It is usually more complicated than that.
* A whole bunch of conditions have to be met for the value A writes to
  blow up B.


<!-- .slide: data-state="normal" id="what-is-reproducer" data-timing="20s" data-menu-title="What is a reproducer?" -->
## What is a reproducer?

<div class="breadcrumbs">Reproducers</div>

And what is Fuzzy Sync for?

* A reproducer is a program which triggers a particular bug in another
  program.

* When a bug is fixed in the kernel, we can write an LTP test which
  reproduces it.
  * This validates the bug fix.
  * Ensures the bug is not reintroduced.
  * Ensures the fix is backported to older kernels.
  * Accidentally finds other bugs.

* A particular data race outcome may be difficult to reproduce.

* Fuzzy Sync helps reproduce bugs which require a particular race
  outcome.


<!-- .slide: data-state="normal" id="simple-race-1" data-timing="20s" data-menu-title="A simple race" -->
## A simple race to get us started

<div class="breadcrumbs">SIMPLE RACE</div>

```c
// Thread A

while (fzsync_run_a(&pair)) {
	winner = 'A';

	fzsync_start_race_a(&pair);
	if (winner == 'A' && winner == 'B')
		winner = 'A';
	fzsync_end_race_a(&pair);
}
```

<!-- .element class="column" -->

```c
// Thread B

while (fzsync_run_b(&pair)) {
	
	
	fzsync_start_race_b(&pair);
	nanosleep(/* for 1ns */);
	winner = 'B';
	fzsync_end_race_b(&pair);
}
```

<!-- .element class="column" -->
* How can `winner` be equal to 'A' and 'B'?
* Will `winner` ever be equal to 'A' when `...end_race_a` and
  `...end_race_b` are synchronised?


<!-- .slide: data-state="normal" id="simple-race-2" data-timing="20s" data-menu-title="A simple diagram" -->
<div class="breadcrumbs">SIMPLE RACE</div>

![Diagram](images/race-time-diagrams.svg)


<!-- .slide: data-state="normal" id="simple-race-3" data-timing="20s" data-menu-title="Simple plots" -->
<div class="breadcrumbs">SIMPLE RACE</div>

## Timing Plots

![Start](images/start_difference.png)
<!-- .element class="column" -->

![End](images/end_difference.png)
<!-- .element class="column" -->

* `winner == 'A'` only once (red circle), when `A` is delayed by roughly 55000ns.
* More about this at [richiejp.com/a-rare-data-race](https://richiejp.com/a-rare-data-race).


<!-- .slide: data-state="normal" id="sendmsg03-1" data-timing="20s" data-menu-title="sendmsg03 1" -->
<div class="breadcrumbs">SENDMSG03</div>

## [sendmsg03](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/sendmsg/sendmsg03.c) and LTP test anatomy

```c
// SPDX-License-Identifier: GPL-2.0-or-later
...
#include "tst_test.h"
#include "tst_fuzzy_sync.h"
...
static struct tst_fzsync_pair fzsync_pair;

static void setup(void)
{
	...
	fzsync_pair.exec_loops = 100000;
	tst_fzsync_pair_init(&fzsync_pair);
}

static void cleanup(void)
{
	...
	tst_fzsync_pair_cleanup(&fzsync_pair);
}

static void *thread_run(void *arg)
{
	int val = 0;

	while (tst_fzsync_run_b(&fzsync_pair)) {
		tst_fzsync_start_race_b(&fzsync_pair);
		setsockopt(sockfd, SOL_IP, IP_HDRINCL, &val, sizeof(val));
		tst_fzsync_end_race_b(&fzsync_pair);
	}

	return arg;
}

static void run(void)
{
	...
	tst_fzsync_pair_reset(&fzsync_pair, thread_run);
	while (tst_fzsync_run_a(&fzsync_pair)) {
		...
		tst_fzsync_start_race_a(&fzsync_pair);
		sendmsg(sockfd, &msg, 0);
		tst_fzsync_end_race_a(&fzsync_pair);

		if (tst_taint_check()) {
			tst_res(TFAIL, "Kernel is vulnerable");
			return;
		}
	}

	tst_res(TPASS, "Nothing bad happened, probably");
}

static struct tst_test test = {
	.test_all = run,
	.setup = setup,
	.cleanup = cleanup,
	.taint_check = TST_TAINT_W | TST_TAINT_D,
	.tags = (const struct tst_tag[]) {
		{"linux-git", "8f659a03a0ba"},
		{"CVE", "2017-17712"},
		{}
	}
};
```

* The LTP library implements `main` and many features
* We declare `struct tst_test test` and implement the test specific logic
* Has some similarities to popular testing frameworks


<!-- .slide: data-state="normal" id="sendmsg03-2" data-timing="20s" data-menu-title="sendmsg03 2" -->
<div class="breadcrumbs">SENDMSG03</div>

```c
// Thread A
int val = 1;
...
while (tst_fzsync_run_a(&fzsync_pair)) {
	SAFE_SETSOCKOPT_INT(sockfd, SOL_IP, 
		                IP_HDRINCL, val);
	tst_fzsync_start_race_a(&fzsync_pair);
	sendmsg(sockfd, &msg, 0);
	
	tst_fzsync_end_race_a(&fzsync_pair);
	...
}
```
<!-- .element class="column" -->

```c
// Thread B
int val = 0;

while (tst_fzsync_run_b(&fzsync_pair)) {

	                                                                   //
	tst_fzsync_start_race_b(&fzsync_pair);
	setsockopt(sockfd, SOL_IP, IP_HDRINCL, 
		       &val, sizeof(val));
	tst_fzsync_end_race_b(&fzsync_pair);

}
```
<!-- .element class="column" -->

* `sendmsg` and `setsockopt` are *system calls* which act on a *socket*
* They are both acting on the same socket (`sockfd`)
* It is clear just from the `fzsync` calls that the test is racing
  `sendmsg` against `setsockopt`.
* For some reason setting `IP_HDRINCL` to zero at the same time as
  sending a message is bad


<!-- .slide: data-state="normal" id="sendmsg03-3" data-timing="20s" data-menu-title="sendmsg03 3" -->
<div class="breadcrumbs">SENDMSG03</div>

```c
// Thread A (net/ipv4/raw.c)
static int raw_sendmsg(..) {
	...
	if (!inet->hdrincl) { //Branch 1
		rfv.iov = msg->msg_iov;
		rfv.hlen = 0;
		err = raw_probe_proto_opt(&rfv, &fl4);
		...
	
	if (!inet->hdrincl) { //Branch 2
		...
		err = ip_append_data(..., &rfv, ...);
```
<!-- .element class="column" -->

```c
// Thread B (net/ipv4/ip_sockglue.c)
static int do_ip_setsockopt(...)
{
	...
	case IP_HDRINCL:
		if (sk->sk_type != SOCK_RAW) {
			err = -ENOPROTOOPT;
			break;
		}
		inet->hdrincl = val ? 1 : 0;
		break;
	...
```
<!-- .element class="column" -->

* `do_ip_setsocket` can set `inet->hdrincl` while `raw_sendmsg` executes.
* We start with `hdrincl = 1`
* It is possible to set `hdrincl = 0` after branch 1, but before branch 2.
* `rfv` will contain uninitialised stack data if branch 1 is not taken.
* There could be other bugs as `inet->hdrincl` is accessed multiple times.


<!-- .slide: data-state="normal" id="sendmsg03-4" data-timing="20s" data-menu-title="sendmsg03 4" -->
<div class="breadcrumbs">SENDMSG03</div>

```sh
st_test.c:1261: TINFO: Timeout per run is 0h 05m 00s
[   33.972676] raw_sendmsg: sendmsg03 forgot to set AF_INET. Fix it!
... TINFO: Minimum sampling period ended
... TINFO: loop = 1024, delay_bias = 0
... TINFO: start_a - start_b: { avg =   104ns, avg_dev =    32ns, dev_ratio = 0.31 }
... TINFO: end_a - start_a  : { avg = 96269ns, avg_dev = 12595ns, dev_ratio = 0.13 }
... TINFO: end_b - start_b  : { avg =  3750ns, avg_dev =   645ns, dev_ratio = 0.17 }
... TINFO: end_a - end_b    : { avg = 92623ns, avg_dev = 12214ns, dev_ratio = 0.13 }
... TINFO: spins            : { avg = 51068  , avg_dev =  7169  , dev_ratio = 0.14 }
... TINFO: Reached deviation ratios < 0.10, introducing randomness
... TINFO: Delay range is [-1839, 48895]
... TINFO: loop = 8354, delay_bias = 0
... TINFO: start_a - start_b: { avg =   109ns, avg_dev =     8ns, dev_ratio = 0.08 }
... TINFO: end_a - start_a  : { avg = 85945ns, avg_dev =  6629ns, dev_ratio = 0.08 }
... TINFO: end_b - start_b  : { avg =  3234ns, avg_dev =    91ns, dev_ratio = 0.03 }
... TINFO: end_a - end_b    : { avg = 82821ns, avg_dev =  6539ns, dev_ratio = 0.08 }
... TINFO: spins            : { avg = 47118  , avg_dev =  4193  , dev_ratio = 0.09 }
[   37.924253] general protection fault, probably for non-canonical address 0xdffffc0000000002: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI
[   37.925000] KASAN: null-ptr-deref in range [0x0000000000000010-0x0000000000000017]
[   37.925411] CPU: 2 PID: 251 Comm: sendmsg03 Not tainted 5.10.4-22-default+ #137
[   37.925946] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
[   37.926555] RIP: 0010:csum_and_copy_from_iter_full+0x2b/0xbc0
...
[   37.931155] Call Trace:
[   37.931292]  ip_generic_getfrag+0x107/0x1a0
[   37.932072]  __ip_append_data+0x1350/0x35c0
[   37.933452]  ip_append_data+0xca/0x170
[   37.933647]  raw_sendmsg+0x884/0x1180
[   37.935890]  sock_sendmsg+0xdd/0x110
[   37.936058]  ____sys_sendmsg+0x5a1/0x7b0
[   37.936905]  ___sys_sendmsg+0xd8/0x160
[   37.938414]  __sys_sendmsg+0xb7/0x140
[   37.939583]  do_syscall_64+0x33/0x40
[   37.939791]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
[   37.940005] RIP: 0033:0x7f5f94fdbebd
...
Test timeouted, sending SIGKILL!
tst_test.c:1299: TFAIL: Kernel is now tainted.

HINT: You _MAY_ be missing kernel fixes, see:

https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8f659a03a0ba

HINT: You _MAY_ be vulnerable to CVE(s), see:

https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-17712
...
```

* Fuzzy Sync loops 8354 times until timing volatility reaches a lower threshold.
* It appears `sendmsg` takes far longer to execute than `setsocketopt`.
* Fuzzy Sync calculates a delay range which will overlap the syscalls in all possible ways.
* Shortly after we start adding random delays we quickly hit a KASAN splat.
* Stale stack data is passed to `ip_append_data` and eventually blows
  up `csum_and_copy_from_iter_full` which tries to dereference part of
  it.


<!-- .slide: data-state="normal" id="sendmsg03-4" data-timing="20s" data-menu-title="sendmsg03 4" -->
<div class="breadcrumbs">SENDMSG03</div>

## sendmsg03 Wrap Up

* Most likely the initial timings are recorded with `hdrincl = 0` for
  all of `raw_sendmsg` because `setsockopt` is much faster. However
  this still results in a good delay range.
* Kernel bug assigned CVE-2017-17712
* Found, fixed and original POC by Mohamed Ghannam
  https://seclists.org/oss-sec/2017/q4/401
* Reproducer converted to LTP Fuzzy Sync by Martin Doucha


<!-- .slide: data-state="normal" id="af_alg07-1" data-timing="20s" data-menu-title="af_alg07 1" -->
<div class="breadcrumbs">AF_ALG07</div>

## [af_alg07](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/crypto/af_alg07.c) (CVE-2019-8912)

```c
// Thread A
while (tst_fzsync_run_a(&fzsync_pair)) {
	sock = tst_alg_setup_reqfd(...);
	tst_fzsync_start_race_a(&fzsync_pair);
	TEST(fchownat(sock, /*this user*/));
	tst_fzsync_end_race_a(&fzsync_pair);
	...
	if (TST_RET == -1 && TST_ERR == ENOENT) {
		tst_res(TPASS | TTERRNO, ...
```
<!-- .element class="column" -->

```c
// Thread B
while (tst_fzsync_run_b(&fzsync_pair)) {

	tst_fzsync_start_race_b(&fzsync_pair);
	dup2(fd, sock);
	tst_fzsync_end_race_b(&fzsync_pair);
}
```
<!-- .element class="column" -->

* Races `fchownat` against `dup2` on a crypto API socket.
* `dup2` has the side effect of closing the socket pointed to by `sock`. 
* `fchownat` accesses the socket, or file, pointed to by `sock`.
* If `errno = ENOENT` is set by `fchownat`, then we hit the race
  window, but the kernel handled it correctly.


<!-- .slide: data-state="normal" id="af_alg07-2" data-timing="20s" data-menu-title="af_alg07 2" -->
<div class="breadcrumbs">AF_ALG07</div>

## Meanwhile in `net/socket.c`
```c
// Thread A, inode lock is held
static int sockfs_setattr(
	struct dentry *dentry /* has sock */, 
	struct iattr *iattr) {
	...
		if (sock->sk)
			sock->sk->sk_uid = iattr->ia_uid;
		else
			err = -ENOENT;
	...
```
<!-- .element class="column" -->

```c
// Thread B
static void __sock_release(
	struct socket *sock, 
	struct inode *inode) {
	...
	if (inode) inode_lock(inode);
 // af_alg_release -> sock_put(sock->sk)
	sock->ops->release(sock);
	if (inode) inode_unlock(inode);
	...
```
<!-- .element class="column" -->

* `__sock_release` (from `dup2`) frees `sock->sk`, but does not set it to `NULL`.
* While `sock->sk` is being freed `fchownat` may be waiting for the `inode` lock (or whatever).
* When `sockfs_setattr` (from `fchownat`) runs we get a *use-after-free* instead of `ENOENT`
* Fix is to set `sock->sk = NULL` with `inode` lock held.


<!-- .slide: data-state="normal" id="af_alg07-3" data-timing="20s" data-menu-title="af_alg07 3" -->
<div class="breadcrumbs">AF_ALG07</div>

## But there is another race

* Passes *quickly* on fixed x86 systems.
* On large ARM64 machines we occasionally get fails on fixed systems.
* `dup2` is "atomic", but...
* There is a window where `dup2` invalidates the socket's file
  descriptor, before re-pointing it to the temp file.
* This causes `fchownat` to return *much quicker* with `EBADF`.
* If this happens consistently, our delay range for `fchownat` will be too short.


<!-- .slide: data-state="normal" id="af_alg07-4" data-timing="20s" data-menu-title="af_alg07 4" -->
<div class="breadcrumbs">AF_ALG07</div>

## Delay bias

```c
if (TST_RET == -1 && TST_ERR == EBADF) {
	tst_fzsync_pair_add_bias(&fzsync_pair, 1);
	continue;
}
```

* When we see `EBADF` we can add a constant delay to `dup2`.
* This ensures `fchownat` has enough time to grab the socket from the
  file descriptor.
* This then means `fchownat` will continue down a longer path.

### Other tests with delay bias

* [CVE-2016-7117](https://github.com/linux-test-project/ltp/blob/master/testcases/cve/cve-2016-7117.c)
* [setsockopt06](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/setsockopt/setsockopt06.c)
* [setsockopt07](https://github.com/linux-test-project/ltp/blob/master/testcases/kernel/syscalls/setsockopt/setsockopt06.c)


<!-- .slide: data-state="normal" id="af_alg07-5" data-timing="20s" data-menu-title="af_alg07 5" -->
<div class="breadcrumbs">AF_ALG07</div>

## Wrapup af_alg07

* Is also a test of Fuzzy Sync's reliability as we *must* hit a race
  window to *pass*.
* Discovered by Syzkaller
* LTP test written by Martin Doucha
* Delay bias added by Li Wang
* Specific fix by [Mao Wenan](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=9060cb719e61b685ec0102574e10337fa5f445ea)
* General fix by [Eric Biggers](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ff7b11aa481f682e0e9711abfeb7d03f5cd612bf)
* More general test(s) based on reproducer by Eric is/are possible.
* One day a kernel change will probably break the test, but sometimes
  we just have to live with that.


<!-- .slide: data-state="normal" id="why-dont" data-timing="20s" data-menu-title="why don't" -->
<div class="breadcrumbs">WHY</div>

## Why don't you just...

* Create many threads or processes
  * Works great for POCs, but...
  * Expensive
  * Terrible and unknown scaling properties
  * Like fishing with dynamite
* Use *X*
  * It works by instrumenting the code (it's invasive, requires `CAP_SYS_ADMIN` etc.)
  * We couldn't find *X*
  * It's usually easier to specifically rewrite something for the LTP anyway
* Add a random sleep
  * That is what Fuzzy Sync does, but we use a *spin wait*
  * Context switching often takes longer than the required sleep
  * Different systems require much different delay ranges.


<!-- .slide: data-state="normal" id="standalone" data-timing="20s" data-menu-title="standalone" -->
<div class="breadcrumbs">STANDALONE</div>

## Standalone edition

### https://gitlab.com/Palethorpe/fuzzy-sync

* Just a single header file
* Only dependency is a compiler with atomic intrinsics
  * POSIX threading is used by default, but can be removed
* Can be easily copied into another project
* Contains example test using CMake/CTest
* [LTP version](https://github.com/linux-test-project/ltp/blob/master/include/tst_fuzzy_sync.h) is still under development, but is fairly stable now
