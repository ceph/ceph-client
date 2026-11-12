# Kernel client port: test plan for a real machine

Draft, updated 2026-11-12 (v4).  Covers the libceph series in this PR, on
ceph-client `testing` (7.4-rc2, which has the read_from_replica fix
d6c7a5fcd088): 30 patches, FIXUPs folded in, the large ones split for
review:

- Part A, needs only ceph.git main (patches 1-20): SERVER_OCTOPUS..
  SERVER_VAMPIRE, pg_pool_t up to v33 and v34, pg_upmap_primaries,
  primary-first pg_temp, EC optimizations as a new interval, pool migration
  (routing; watermark redirects; debugfs; linger moves), multi-op reply data,
  CephFS version reads from the primary, the pool's tiering and dedup tier,
  EC direct reads (single chunk, one-shot shard requests, split reads with
  GET_INTERNAL_VERSIONS_V2, or GET_INTERNAL_VERSIONS after an OSD refuses
  _V2).
- Part B, waits for ceph PRs 72643 and 73794 (patches 21-24): bit 54
  (OSD_STRETCH_ZONES / POOL_MIGRATION), pg_pool_t v35 (num_zones),
  zone-aware direct reads.
- KUnit tests (CONFIG_CEPH_LIB_KUNIT_TEST, patches 25-30, one per area),
  and a DNM debugfs counters patch used by the test harness, which stays out
  of the series.

The local test scripts named below belong to a harness (qemu guests against a
vstart cluster) that is not published yet.

## 1. What the local runs cannot show

Local runs use qemu with software emulation (no KVM), a vstart cluster with
memstore OSDs on one host, and debug kernels (KASAN, lockdep).  They prove
behaviour and data integrity, not:

- performance: latency and throughput of direct and split reads versus
  primary reads, and the CPU cost of the split-read copy;
- real networks: zones with real latency between them, packet loss;
- scale: many PGs, many clients, long runs, memory pressure;
- BlueStore: the EC overwrite and partial-write paths that memstore skips;
- real failure: OSD hosts power-cycled, network partitions between zones;
- other kernel users: CephFS with many clients, fscrypt, rbd with
  krbd features (exclusive lock, object map), multipath of rbd devices.

## 2. Machine and cluster

- One host with KVM (or bare metal for the client side), >= 32 cores,
  >= 128 GiB RAM, several NVMe devices (or partitions) for BlueStore OSDs.
- Ceph: the same combined build as locally
  (https://github.com/ceph/ceph/pull/69112,
  https://github.com/ceph/ceph/pull/72643 and
  https://github.com/ceph/ceph/pull/73794),
  release build (RelWithDebInfo), vstart with BlueStore on real devices, or
  cephadm in containers if available.
- Layout for stretch tests: two zones (datacenters) of 4-6 hosts each, one
  OSD per device; host buckets can be emulated per device on one machine.
  Use `tc netem` on the OSD/client network namespaces for inter-zone latency
  (e.g. 2 ms and 10 ms) where daemons run in separate namespaces.
- Kernels: this series built with a production config (no KASAN) for
  performance, and with the debug config for the functional repeats; an
  unpatched kernel of the same base as the control.
- Clients: KVM guests (4-8 vCPUs, virtio-net) and the host kernel itself.

## 3. Functional repeats (from the local harness)

Run each with the patched and the unpatched kernel; the unpatched one is the
control (expected to pass, be refused, or show the documented limitation).

| Test | Local script | Expect (patched) | Expect (unpatched) |
|---|---|---|---|
| RBD I/O on replicated, EC 4+2, EC over 2 zones, replicated over 2 zones | rbd-io.cmd, rbd-spread.cmd | data OK | data OK |
| Primary-first pg_temp (stop an OSD holding shard 0) | t2 recipe | ops carry the real shard (s4) | OSD corrects s1 |
| pg_upmap_primaries | t3 recipe | I/O OK | refused (SERVER_REEF) |
| Pool migration (replicated) under I/O, then resize | t-migrate.sh | MIG OK, redirects counted | refused / EIO while migrating |
| Migration of EC pools (replicated -> EC, EC -> EC, EC -> replicated) with direct reads on | to add | data OK, no direct reads while the pool migrates | - |
| Cascaded migration (second migration before the first ends) | to add | MIG OK | - |
| Client maps or mounts mid-migration | to add | data OK | - |
| OSD failure during a migration | to add | data OK | - |
| CephFS data pool migration | to add | data OK | - |
| EC direct reads, balance | t-zones.sh, rbd-spread.cmd | direct and split counters > 0, data OK | primary reads only |
| Localize to a zone | t-zones.sh | all direct reads in the client's zone | - |
| Torn reads | torn.cmd | 0 torn, fallbacks > 0 | 0 torn (primary reads) |
| OSD failure during direct reads | t-osdfail.sh | data OK, eagain/fallback counted | data OK |
| CephFS on EC data pool | cephfs-ec.cmd | data OK incl. truncate | data OK |

## 4. New on the real machine

Order: migration (5) and torn reads on BlueStore (3) first, as the least
covered and the riskiest; then performance, zones, failures, the soak,
regressions (9) and mixed releases.

1. **Performance, direct reads.** fio (`--ioengine=libaio --direct=1`) on krbd
   images in an EC 4+2 and an EC 8+3 pool, 4 KiB to 4 MiB random and
   sequential reads, queue depth 1-64, read_from_replica=no vs balance.
   Record IOPS, latency percentiles, client and OSD CPU.  Expect lower latency
   for chunk-sized reads (one hop) and higher OSD-side parallelism for large
   reads; check the copy cost of split reads with perf.
2. **Zones.** The same with a 2-zone EC pool and netem latency between zones:
   read_from_replica=localize with crush_location must keep reads in the
   local zone (OSD op counters per zone) and show the latency gain.
3. **Torn-read stress.** Many writers and readers on overlapping extents
   (fio verify with `verify_backlog`, plus torn.cmd scaled up); count
   fallbacks; zero data errors.
4. **Failure.** Power off a host (or kill all OSDs of a host) during
   direct reads; partition one zone from the other and from the client; all
   I/O must complete with correct data or stall and resume, never return
   wrong data.
5. **Migration at scale.** First add a debugfs counter of migration redirects
   and resends to the kernel and raise the OSD debug level, so that each test
   shows the redirect path ran (nothing local proves it did yet).  Migrate a
   pool of 100+ GiB with several kernel clients doing mixed I/O (fio verify):
   replicated -> EC, EC -> EC with a different profile and EC -> replicated,
   with direct reads on.  Cascade a second migration; map or mount a new
   client mid-migration; stop OSDs and a whole host during a migration;
   migrate a CephFS data pool; check that an unpatched kernel is refused and
   that the pool migration compat policing of
   https://github.com/ceph/ceph/pull/73794 covers kernel clients; delete the
   old stub.  Watch for redirects (counter and OSD log), that client latency
   recovers after each PG migrates, and that the monitors drop their
   migration ops when it ends (see 6).  Linger requests (review: Bill Scales): a krbd watch on the
   image header whose object migrates (rbd resize from userspace during and
   after the migration, the kernel sees each size), notifies to the kernel
   during a migration (its acks arrive: no notify timeouts), and notifies
   from the kernel (exclusive-lock handover between krbd and a librbd
   writer while the pool migrates), on replicated and EC pools.
6. **Long soak.** 24 h of mixed I/O with OSD thrashing (random OSD stop/start,
   pg_num changes on non-migrating pools, upmap balancer on) on the debug
   kernel with kmemleak on: no KASAN, kmemleak, lockdep or data errors.
7. **CephFS.** Several kernel clients on a directory with an EC layout, mixed
   reads, writes, truncates, snapshots (snapshot reads take the primary path),
   fscrypt on one directory.
8. **Mixed releases.** Patched kernel against a Tentacle/Umbrella cluster (no
   bit 54, older pool encodings): must work as before; against a cluster with
   `require_min_compat_client` set to squid: refused while the kernel lacks
   CRUSH_MSR (known gap, see 6).
9. **No regressions for existing users.** xfstests on CephFS (generic and
   ceph groups) and the teuthology krbd and kcephfs suites with this kernel;
   builds for 32-bit targets (64-bit division in the stripe maths) and a
   big-endian guest (s390x under qemu) for the new decoders; KUnit tests for
   the pure helpers (pool decoding, primary-first order, stripe maths).
10. **Split-read assembly and lifetime (added 2026-11-12, F6).** Every kernel
   under test, on its own compiler: a CephFS file whose 4 KiB blocks each hold
   their own byte, read back in one 128 KiB read with balance (sparse-diag:
   every block right, including when the other shards bounce with EAGAIN and
   the read falls back); the torn-read test must show fallbacks whenever
   reads race writes (0 fallbacks over 200 racing reads is a failure, not a
   pass); kmemleak on and scanned after the split-read tests (no ceph
   objects).  KUnit: the split tests allocate through alloc_ec_split() and
   check num_subs (kzalloc_flex() sets a __counted_by() counter only on
   compilers with __builtin_counted_by_ref).  A split read cancelled and
   freed by its owner while its sub-reads are out (an interrupted
   ceph_osdc_wait_request()) must not be touched when they complete:
   split_read_cancel_release_test under KASAN.
11. **Chaos with kernel clients (added 2026-11-12, owner: "I want to see
   pool migration in the mix of vstart_chaos").**  vstart_chaos (ceph PR
   72412) drives a second cluster on the machine (harness/chaos/: BlueStore
   on files, 12 OSDs in dc1/dc2, tiebreaker mon in dc3) while its workloads
   are kernel clients in KVM guests: the krbd verify loop on images with
   read_from_replica=balance, localize (crush_location in each zone) and
   none, ms_mode legacy/crc/secure, and a CephFS loop (write, cold read
   whole/ranges/O_DIRECT, overwrite, truncate, extend) on an EC data pool.
   Guests restart when they finish, so clients also map and mount mid-chaos;
   each fails on bad data, any kernel WARN/BUG/KASAN/lockdep/hung-task report
   or kmemleak leak, and the run stops if a guest makes no progress for 15
   minutes.  Chaos actions: OSD down/kill/out/reweight/primary-affinity,
   upmaps, pg_num splits and merges, repeer, deep scrub, and on the two-zone
   pools zone_partial and zone failovers (pool stretch mode); quiesce with
   deep scrub every 30 cycles.  Pool migration runs as a workload
   (pool_migrator.py) on the pools the kernel uses: replicated -> EC, EC ->
   EC with another k (and another zone layout), EC -> replicated, plus
   refused cascades.  Not tested before: chaos ran with a migrate workload
   on 2026-10-27, librados clients only.  Runs:
   - Z: every pool over two zones (EC 4+2 per zone, replicated 3 per zone),
     zone faults, migrations between the two-zone layouts.
   - U: upgrade: the cluster starts on Umbrella (v21.2.0) with kernel
     clients running (split reads switch to GET_INTERNAL_VERSIONS once per
     client), is upgraded under load onto the series' Ceph build (rolling
     mon and OSD restarts, upgrade_cluster.sh), then runs chaos with
     migrations on single-zone pools (replicated, EC 4+2, EC 8+3, CephFS on
     EC 4+2).
   Decisions (chaos fork, 2026-11-12 night, owner unavailable):
   - A second cluster beside the main one (file-backed BlueStore, own
     ports), so the main cluster's runs and repros go on undisturbed.
   - librados probes read with policy none: balanced/localized librados
     reads abort in Objecter on migration redirects (tracker 81981, fixed by
     ceph PR 72977, which the tree lacks); the kernel clients are the
     subject.
   - Two-zone migrations name template pools' CRUSH rules and profiles: a
     migrate from layout arguments alone reuses the source's rule and is
     refused for another layout.  Two-zone EC stays 4+2 per zone (another
     k needs a rule the monitors only allow with require_min_compat_client
     vampire, which the migration workload's pool_migration setting
     replaces).  EC -> EC with another k is covered in the single-zone run
     (4+2 <-> 8+3).
   - CephFS clients only in the single-zone runs (vstart's CephFS metadata
     and data pools are single-zone, so zone failovers would just stall
     them).
   - Kernel: m04fix (PR head + the N3 fix) until main names the final
     series' kernel; then the later runs use that.
   - V1 check: the notice must appear at most once per libceph client (an
     RBD map or a CephFS mount; fs-loop remounts every 5 cycles), split
     reads must keep counting after it, and a client booted after the
     upgrade must print none.
   Results (2026-11-13, TEST-RECORD "chaos runs with kernel clients"):
   - Upgrade under load (U3, m04fix): PASS.  Umbrella v21.2.0 -> the series'
     Ceph, mons and OSDs one by one under five clients; the V1 notice once
     per libceph client against Umbrella OSDs, split reads went on with V1
     (38073 splits), a client booted after the upgrade used V2.
   - Stretch EC chaos: Z6 (v3b) complete, 100 cycles, kernel PASS (600
     cycles, 0 errors, kmemleak 0) through six zone failovers, a partial
     zone loss and four migrations; Z2 (m04fix) and Z4 (v3b) kernel PASS
     too (1719 and 767 cycles).
   - Single-zone chaos on the upgraded cluster: S3 and S4 (v3b) kernel PASS
     (1773 and 1590 cycles, 0 errors), 17 migrations incl. EC 4+2 <-> 8+3
     <-> replicated under the clients.
   - Kernel bug found: N4 (S4): requests lost across a PG merge of a
     migration target; recreated on v3b and shown fixed on v3c (R1).
   - Ceph/harness only otherwise: known librados Objecter assert on
     migration redirects (81981/PR 72977), known PGLog.h:676 assert
     (81283/PR 72290), a pool migration stalled on an empty source PG,
     migration stubs' PGs not scrubbing on request, orphaned guests ->
     duplicate addresses (fixed), Umbrella mgr/MDS blocking migrations
     until upgraded (correct policing).

## 4a. Design decisions and the tests that cover them

| Decision | Why | Test |
|---|---|---|
| Split reads use GET_INTERNAL_VERSIONS_V2; after an OSD fails that op itself with -EOPNOTSUPP (not the read op: Bob's review item 6, 2026-11-12) the client switches to GET_INTERNAL_VERSIONS (V1) with the primary as the reference shard (owner, 2026-11-12) | Userspace picks by require_osd_release, which is in the OSD part of the map that libceph doesn't decode (Ilya, a561372405cf); per-OSD peer_features checks were removed by Ilya for being unreliable | KUnit: ec_split_versions_test, ec_split_versions_v1_test, split_read_v1_test (-EOPNOTSUPP switches to V1 once, versions-only primary reference); VM: split reads against an Umbrella cluster (V1 after one fallback, data OK, torn-read test), against Vampire (V2 only), and an Umbrella->Vampire upgrade under load |
| Split reads are not used while the pool takes part in a migration; single-chunk direct reads are | Sub-reads pick shards once; a watermark move can send a sub-read to a pool with another EC layout | KUnit: split_read_migration_test; VM: EC->EC migration with a different k under read_from_replica=balance, data verified; counters show no splits during the migration and splits after |
| Reads whose reply version is used (CephFS fscrypt RMW and truncate) go to the primary | Non-primary shards of optimized EC pools can lag, split reads carry no version (F1) | KUnit (libceph side only; fs/ceph has no KUnit): version_read_test; VM: fscrypt directory on the EC data pool with balance, unaligned writes and truncates, data verified |
| Localized reads use one local zone per read (first OSD of each zone) and fall back to the primary if a shard is missing there; balanced reads pick a random readable zone per shard | Mirrors SplitOp (F2) | KUnit: ec_choose_read_shard_test, localize_zone_test, balance_zones_test; VM: zone tests (localize stays in zone; remote zone down; local shard down -> primary) |
| A direct read whose PG changes, or that sees any new interval (e.g. min_size), goes to the primary, also when a pool migration moves it to a replicated pool (2026-11-12, N3) | Mirrors Objecter FORCE_OSD handling; OSDs drop direct reads of an earlier interval (F3); OSDs refuse EC direct reads on pools without EC optimizations with -EOPNOTSUPP (since ceph PR 72651) | KUnit: direct_read_pg_change_test, direct_read_interval_test, direct_read_migrating_test, split_read_interval_test, direct_read_migration_redirect_test; VM: direct reads under min_size changes, primary_temp moves and OSD down/up; M04 (EC 4+2 -> replicated under balance reads) |
| EC optimizations being enabled on a pool is a new interval | OSDs start a new interval then; no forced resend from the mons | KUnit: ec_optimizations_interval_test, new_interval_test; VM: enable allow_ec_optimizations on a pool under krbd I/O, no hung requests |
| Ops for a migration target or latest source flagged EIO are sent there, for its OSDs to fail them | The kernel doesn't set SUPPORTSPOOLEIO, so OSDs reply -EIO | KUnit: calc_migration_target_test; VM: set eio on the target during a migration |
| Linger requests move on a migration redirect | Mirrors Objecter (review: Bill Scales asked for watch/notify/ack tests) | KUnit: migration_linger_test, migration_redirect_test (resend order, forward-only watermark); VM: watch, notify to and from the kernel, and notify acks during and after migrations (section 4.5) |
| KUnit tests run the client's real paths: maps encoded as the monitors do (CRUSH included) through handle_one_map(), OSD replies through handle_reply(), reply data through osd_sparse_read(), sessions that never connect | Every defect fixed in the series needs a test that fails without its fix (owner, 2026-11-12) | net/ceph/osdmap_kunit.h framework; suites ceph_osdmap, ceph_osd_client{,_target,_split,_reply,_migration}; each fix shown failing on a scratch revert (FINDINGS-1112.md, KUnit recreate tests) |
| A split read's completion (assembly, result, fallback to the primary) runs under osdc->lock, for read when it completes and for write when it resends; the callback runs after the lock is dropped; the split keeps the OSD client (Bob's review items 1-2, 2026-11-12) | ceph_osdc_cancel_request() must leave nothing in flight and must not reach a freed split | KUnit: split_read_cancel_release_test, split_read_cancel_fallback_test, split_read_cancel_complete_test (each fails without the fix); VM: cancelled/interrupted reads under load (krbd unmap during I/O, kill of CephFS readers) with KASAN |
| The watermark entry of a PG is allocated before osdc->lock is taken for write; if it can't be and the PG has none, the redirected request fails with -ENOMEM (Bob's review item 3, 2026-11-12) | No redirect loop under memory pressure; Objecter can't fail there | KUnit: migration_wm_nomem_test (fix only: the allocation failure can't be injected without a hook) |
| Pools of size 0 are refused at decode, whatever the encoding (Bob's review item 4) | The zone helpers divide by the zone size | KUnit: pool_v35_test size-0 cases |
| EC direct reads only from pools that allow non-primary reads as pg_pool_t::allows_nonprimary_reads(): not a tier, no tiers, no dedup tier; tier_of, tiers and the pool options' dedup tier are decoded for it. Replica reads of replicated pools are unchanged (mainline never checked) (Bob's review item 5, 2026-11-12) | Objecter parity | KUnit: ec_direct_read_pool_test, direct_read_tier_test |
| Advertising SERVER_QUINCY makes monitors encode every CRUSH rule's sizes as 1..100, so rules match any pool size (Bob's review item 7: stated in the commit message) | CrushWrapper::encode() | KUnit: osdmap_crush_rule_size_test; VM: every suite maps pools of size 3-12 |
| A request also follows the force resend epoch of the pool a migration sends it to, not only its base pool's (N4, chaos run S4, 2026-11-13) | libceph learns of PG merges only from that epoch (v25, last_force_op_resend_prenautilus, set at each merge step), and a migrated pool is merged in its target; the merge source's OSDs drop the requests and the merge target shares its OSDs, so nothing else resends | KUnit: migration_merge_test (fails without the fix); VM R1: merge a pool whose migration has finished (pg_num 32 -> 16) under KVM krbd writes, v3b (a request stays pending on a merged-away PG) vs v3c (requests move with each merge step, no stall) |
| The debugfs counters patch stays out of the upstream series (DNM) | Style review: libceph debugfs shows state, not counters | Harness keeps reading EC_DIRECT_READS from test kernels only |
| Part A and Part B are reviewed and tested separately | Part B depends on unmerged ceph PRs | Run the suites with a Part A kernel against a main-only build, and with A+B against the combined build |

## 5. Pass criteria

- No data mismatches in any test; no KASAN, lockdep, WARN or BUG in the
  debug kernel runs.
- Every local functional test passes on the real machine.
- Direct reads used whenever eligible (counters), fallbacks only when
  writes race or OSDs change.
- Every migration test shows redirects in the counter and the OSD log.
- Performance results recorded with the configuration; any regression
  against read_from_replica=no explained.

## 6. Known gaps to track

- Ceph side (for the owner): v21 OSDs return -EINVAL to writes that carry
  BALANCE_READS/LOCALIZE_READS, which unpatched kernels set on CephFS writes
  when mounted with read_from_replica (fixed on the kernel side by
  d6c7a5fcd088, in 7.4-rc1).
- Ceph side: a migrated pool's stub keeps SERVER_VAMPIRE required of every
  client until it is deleted, so unpatched kernels can't connect.
- Ceph side: after one local migration a non-leader monitor kept 33
  `osd_pg_migrate_pool` ops (SLOW_OPS) long after it finished; seen once,
  not investigated.
- CRUSH MSR rules (bit 38) are not supported by the kernel, so monitors
  classify it as Reef-like: `require_min_compat_client >= squid` needs
  `--yes-i-really-mean-it` while kernel clients are connected.
- Split reads need an established session (SERVER_VAMPIRE) with every
  shard's OSD; the first reads of a fresh client go through the primary.
- Split reads copy the shards' data into the caller's buffer; zero-copy
  receive into the caller's pages is possible later.
- Replica split reads (ReplicaSplitOp) are not ported.
- pool_opts dedup_tier is not decoded; Objecter refuses direct reads on such
  pools (allows_nonprimary_reads()).
- CephFS reads carry truncate_seq/size; direct reads pass them to the shard
  as Objecter does; worth a dedicated truncate race test on BlueStore.
