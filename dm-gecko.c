
/*
 * Copyright (C) 2011 Tudor Marian <tudorm@cs.cornell.edu> (see
 * LICENSE file)
 */

#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/hash.h>
#include <linux/highmem.h>
#include <linux/hrtimer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pagemap.h>
#include <linux/percpu.h>
#include <linux/random.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <scsi/sg.h>

#include "dmg-kcopyd.h"

//#define ALWAYS_RUN_GC
#define DROP_WRITE_WRITE_CLASH_OPTIMIZATION
//#define SYS_RENAME_EXPORTED_TO_MODULES

//#define MAX_DETAIL_LOG_LOOP_CNT 0xffffffff
#define MAX_DETAIL_LOG_LOOP_CNT 8

#define MIN_JOBS_IN_POOL        512
#define DM_GECKO_GC_COPY_PAGES  512
#define DM_GECKO_MAX_STRIPES    DMG_KCOPYD_MAX_REGIONS
#define MIN_GC_CONCURRENT_REQ   4
#define GC_CONCURRENT_REQ       64
#define MAX_GC_CONCURRENT_REQ   DM_GECKO_GC_COPY_PAGES

#define GC_DEFAULT_LOW_WATERMARK         0
#define GC_DEFAULT_HIGH_WATERMARK        3
#define DM_GECKO_CRITICAL_WATERMARK      1024
#define DM_GECKO_CRITICAL_WATERMARK_HARD 8

#define DM_GECKO_DEBUG 0
#define DM_GECKO_PREFIX "dm-gecko: "
#if DM_GECKO_DEBUG
#define DPRINTK( s, arg... ) printk(DM_GECKO_PREFIX s "\n", ##arg)
#else
#define DPRINTK( s, arg... )
#endif

#define GECKO_TIMER_PERIOD_SECS         (1)
#define GECKO_TIMER_PERIOD_NSECS        (0)

#define GECKO_BLOCK_SHIFT PAGE_SHIFT        /* blocks the size of pages */
#define GECKO_BLOCK_SIZE (1UL << GECKO_BLOCK_SHIFT)

#define GECKO_SECTOR_TO_BLOCK_SHIFT (GECKO_BLOCK_SHIFT - SECTOR_SHIFT)
#define GECKO_SECTOR_TO_BLOCK_MASK ((1UL << GECKO_SECTOR_TO_BLOCK_SHIFT) - 1)
#define GECKO_SECTORS_PER_BLOCK (1UL << GECKO_SECTOR_TO_BLOCK_SHIFT)

static inline sector_t sector_to_block(sector_t sector)
{
        return (sector >> GECKO_SECTOR_TO_BLOCK_SHIFT);
}

static inline sector_t block_to_sector(sector_t sector)
{
        return (sector << GECKO_SECTOR_TO_BLOCK_SHIFT);
}

static inline int sector_at_block_boundary(sector_t sector)
{
        return ((sector & GECKO_SECTOR_TO_BLOCK_MASK) == 0x0);
}

static inline int bio_start_at_block_boundary(struct bio *bio)
{
        return sector_at_block_boundary(bio->bi_sector);
}

static inline int bio_end_at_block_boundary(struct bio *bio)
{
        return sector_at_block_boundary(bio->bi_sector +
                                        to_sector(bio->bi_size));
}

static inline int bio_at_block_boundary(struct bio *bio)
{
        return bio_start_at_block_boundary(bio)
            && bio_end_at_block_boundary(bio);
}

static inline int bio_single_block_at_block_boundary(struct bio *bio)
{
        return (bio->bi_size == GECKO_BLOCK_SIZE)
            && bio_at_block_boundary(bio);
}

enum seg_power_state {
        unspecified,
        active,      /* normal active/idle operation mode */
        standby,     /* low power mode, drive has spun down */
        sleep,       /* lowest power mode, drive is completely shut down */
};

#define DEFAULT_LOW_POW_STATE standby

struct dm_gecko;

struct dm_dev_seg {
        struct list_head list;
        int idx;          /* only used for debugging purposes */
        sector_t start;   /* offset in sectors */
        sector_t len;     /* len in sectors */
        struct dm_dev *dev[DM_GECKO_MAX_STRIPES];
        struct work_struct work;
        enum seg_power_state cur_pow_state, next_pow_state;
        unsigned long long access_seq_in_log;
        atomic_t pending_writes;
        struct dm_gecko *ctxt;
};

enum dm_gecko_layout { linear, raid0, raid1, raid5, raid6 };

struct phy_disk_map {
        sector_t len;                /* total linear length in sectors */
        enum dm_gecko_layout layout;
        int stripes;
        int cnt;
        struct list_head dm_dev_segs;
};

/* Hashtable for pending IO operations indexed by block number */
#define HASH_TABLE_BITS 12
#define HASH_TABLE_SIZE (1UL << HASH_TABLE_BITS)

struct dm_gecko_stats {
        unsigned long long reads, subblock_reads, writes, subblock_writes,
            gc, discards, dropped_discards, empty_barriers, gc_recycle,
            rw_clash, rw_gc_clash, gc_clash, gc_rw_clash, ww_clash,
            read_empty, read_err, write_err, kcopyd_err, sb_read, sb_write;
};

struct gc_ctrl {
        u32 low_watermark;
        u32 high_watermark;
};

enum {  // dm_gecko->flags bit positions
        DM_GECKO_GC_FORCE_STOP,
	DM_GECKO_FINAL_SYNC_METADATA,
	DM_GECKO_GC_STARTED,
	DM_GECKO_READ_TPUT,
	DM_GECKO_INDEPENDENT_GC,
	DM_GECKO_STATUS_DETAILED,
	DM_GECKO_SYNCING_METADATA,
};

struct dm_gecko {
        spinlock_t lock;
        atomic_t total_jobs;    /* used to safely destroy the target */
        struct list_head *buckets;
        int htable_size;
        u32 *d_map;             /* direct map */        
        u32 *r_map;             /* reversed map */
        u32 tail;
        u32 persistent_tail;
        u32 head;
        u32 size;                /* size of the maps in number of blocks */
        /* free blocks that can be used w/o reclaiming initialized to
           ->size.  Circular ring logic dictates that available_blocks
           must be > 1 */
        u32 persistent_available_blocks;
        u32 available_blocks;
        u32 free_blocks;        /* total number of free blocks */
        struct dm_dev_seg *head_seg;
        struct dm_dev_seg *tail_seg;
        volatile unsigned long flags;
        int gc_req_in_progress;
        int max_gc_req_in_progress;
        struct phy_disk_map disk_map;
        struct dmg_kcopyd_client *kcopyd_client;
        struct dm_io_client *io_client;
        struct dm_gecko_stats *stats;
        struct gc_ctrl gc_ctrl;
        struct hrtimer timer;
        ktime_t timer_delay;
        struct work_struct gc_work;
        atomic_t timer_active;
        atomic_t gc_work_scheduled_by_timer;
        struct work_struct sync_metadata_work;
        wait_queue_head_t jobs_pending_waitqueue;
        wait_queue_head_t no_free_space_waitqueue;
        struct rw_semaphore metadata_sync_sema;
        enum seg_power_state low_pow_state;
        unsigned long long incarnation;
        unsigned long tail_wrap_around;
        unsigned long head_wrap_around;
        char *meta_filename;
};

struct dm_gecko_dev {
        char name[16];  // for the persistent metadata representation
};

/* TUDORICA, the diminutive form of my name (Tudor) in Romanian ;) */
#define DM_GECKO_META_MAGIC (0x2D0031CA)

/* the persistent dm_gecko starts w/ this header on disk, followed by
   all the disk_map_cnt device names of (struct dm_gecko_dev) type,
   and by block maps */
struct dm_gecko_persistent_metadata {
        unsigned long long incarnation;
        u32 magic;
        u32 size;
        u32 tail;
        u32 head;
        u32 available_blocks;
        u32 free_blocks;
        unsigned long flags;
        int max_gc_req_in_progress;
        enum dm_gecko_layout layout;
        int stripes;
        int disk_map_cnt;
        struct gc_ctrl gc_ctrl;
        enum seg_power_state low_pow_state;
};

struct io_for_block {
        sector_t key;
        int rw_cnt;                     /* number of IOs in progress. If
                                         * negative, the gc is running */
#define WRITE_CLASH_IO_FOR_BLOCK 0
        volatile unsigned long flags;   /* for write_clash optimization */
        struct list_head hashtable;     /* chain into the hash table */
        struct list_head pending_io;    /* list of IOs in progress */
        struct list_head deferred_io;   /* list of deferred IOs */
};

struct io_job {
        struct list_head list;
        struct dm_gecko *dmg;
        int rw;                        /* READ or WRITE */
        struct io_for_block *parent;   /* if NULL, the job is deferred */
        void *page;                    /* for read-modify-update cycles */
        struct bio *bio;               /* if NULL this is a gc IO */
        sector_t v_block;              /* virtual block */
        sector_t l_block;              /* linear block */
};

static inline int sector_in_seg(sector_t sector, struct dm_dev_seg *seg)
{
        return (sector >= seg->start) && (sector < seg->start + seg->len);
}

static struct dm_dev_seg *seg_for_sector(struct dm_gecko *dmg,
                                                sector_t sector)
{
        struct dm_dev_seg *seg;
        list_for_each_entry(seg, &dmg->disk_map.dm_dev_segs, list) {
                if (sector < seg->start + seg->len) {
                        return seg;
                }
        }
        return NULL;
}

static inline void linear_to_phy_raid0(struct dm_gecko *dmg,
				       struct dm_dev_seg *seg,
				       sector_t sector,
				       struct dm_io_region *where)
{
        int stripe;
	sector_t block;
	sector -= seg->start;
	block = sector_to_block(sector);
	// The do_div is a macro that updates @block with the
	// quotient and returns the remainder. Use block instead
	// of the sector, since all sectors, being block aligned,
	// are even, so the stripe is always 0.
	stripe = do_div(block, dmg->disk_map.stripes);
	where->bdev = seg->dev[stripe]->bdev;
	where->sector = block_to_sector(block);
	where->count = GECKO_SECTORS_PER_BLOCK;
}

static struct dm_dev_seg *linear_to_phy_all(struct dm_gecko *dmg,
					    sector_t sector,
					    struct dm_io_region *where,
                                            int *num_regions)
{
        int i;
        struct dm_dev_seg *seg = seg_for_sector(dmg, sector);

        BUG_ON(!seg);  /* must fit in the range somewhere */

	if (dmg->disk_map.layout == raid0) {
		linear_to_phy_raid0(dmg, seg, sector, &where[0]);
		*num_regions = 1;
	} else {
	        for (i = 0; i < dmg->disk_map.stripes; i++) {
		        where[i].bdev = seg->dev[i]->bdev;
			where[i].sector = sector - seg->start;
			where[i].count = GECKO_SECTORS_PER_BLOCK;
		}
                *num_regions = dmg->disk_map.stripes;
	}
        return seg;
}

static struct dm_dev_seg *linear_to_phy_which(struct dm_gecko *dmg,
					      sector_t sector,
					      unsigned which,
					      struct dm_io_region *where)
{
        struct dm_dev_seg *seg = seg_for_sector(dmg, sector);

        BUG_ON(!seg);  /* must fit in the range somewhere */
        BUG_ON(which >= dmg->disk_map.stripes);

	if (dmg->disk_map.layout == raid0) {
		linear_to_phy_raid0(dmg, seg, sector, where);
	} else {
	        where->bdev = seg->dev[which]->bdev;
		where->sector = sector - seg->start;
		where->count = GECKO_SECTORS_PER_BLOCK;
	}
        return seg;
}

static inline u32 mark_block_free(struct dm_gecko *dmg)
{
        return dmg->size;
}

static inline int is_block_marked_free(u32 block, struct dm_gecko *dmg)
{
        return (block == dmg->size);
}

static inline int is_block_invalid(u32 block, struct dm_gecko *dmg)
{
        return (block > dmg->size);
}

static inline int is_block_free_or_invalid(u32 block, struct dm_gecko *dmg)
{
        return (block >= dmg->size);
}

static inline int __no_available_blocks(struct dm_gecko *dmg)
{
        /* can be less than the watermark temporarily while gc runs */
        return (dmg->available_blocks <= DM_GECKO_CRITICAL_WATERMARK);
}

static inline int __no_available_blocks_hard(struct dm_gecko *dmg)
{
        return (dmg->available_blocks <= DM_GECKO_CRITICAL_WATERMARK_HARD);
}

/* used by all dm-gecko targets */
static DEFINE_SPINLOCK(jobs_lock);
/* the workqueue picks up items off this list */
static LIST_HEAD(deferred_jobs);

/* mempool cache allocators */
static struct kmem_cache *io_for_block_cache, *io_job_cache;
static mempool_t *io_for_block_mempool, *io_job_mempool;

/* Deferred work and work that needs a task context executes on this
 * workqueue. Must be singlethreaded. */
static struct workqueue_struct *gecko_wqueue = NULL;
static struct work_struct gecko_work;
/* This workqueue is used only to sync the metadata from a
task-context. Trying to use the same gecko_wqueue for this operation
would render the deadlock avoidance logic unnecessarily complicated. */
static struct workqueue_struct *gecko_sync_metadata_wqueue = NULL;

struct deferred_stats {
        unsigned long long gc, rw, total;
};
DEFINE_PER_CPU(struct deferred_stats, deferred_stats);

static  void do_complete_generic(struct dm_gecko *dmg)
{
        if (atomic_dec_and_test(&dmg->total_jobs)) {
                wake_up(&dmg->jobs_pending_waitqueue);
        }
}

static void do_run_gc(struct io_job *io);
static void map_rw_io_job(struct io_job *io);

static inline void wake_deferred_wqueue(void)
{
        queue_work(gecko_wqueue, &gecko_work);
}

static inline int io_job_is_deferred(struct io_job *io)
{
        return (io->parent == NULL);
}

static inline void set_io_job_deferred(struct io_job *io)
{
        io->parent = NULL;
}

static inline int io_job_is_gc(struct io_job *io)
{
        return (io->bio == NULL);
}

static inline void set_io_job_gc(struct io_job *io)
{
        io->bio = NULL;
}

static inline void __add_deferred_io_job(struct io_job *io)
{
        set_io_job_deferred(io);
        list_add_tail(&io->list, &deferred_jobs);
}

static void queue_deferred_io_job(struct io_job *io)
{
        unsigned long flags;
        struct deferred_stats *def_stats;

        spin_lock_irqsave(&jobs_lock, flags);
        def_stats = &__get_cpu_var(deferred_stats);
        __add_deferred_io_job(io);
        ++def_stats->total;
        spin_unlock_irqrestore(&jobs_lock, flags);

        wake_deferred_wqueue();
}

/* The only entry point into the gc; can be called from interrupt context */
static void wake_gc(struct io_job *io)
{
        set_io_job_gc(io);
        io->page = NULL;
        queue_deferred_io_job(io);
}

/* Runs on the global workqueue, serialized w/ the IO completion
 * work_structs since the workqueue is singlethreaded. */
static void try_sched_gc(struct work_struct *work)
{
        struct dm_gecko *dmg = container_of(work, struct dm_gecko, gc_work);
	struct io_job *io;
	int i;

	// Optimistic estimate of the # of gc requests that can be
	// issued --- read the dmg->gc_req_in_progress without holding
	// the dmg->lock.
	int gc_requests = (dmg->max_gc_req_in_progress -
			   dmg->gc_req_in_progress);
	if (gc_requests < 1) {
	  gc_requests = 1;
	}

	for (i = 0; i < gc_requests; ++i) {
	  atomic_inc(&dmg->total_jobs);
	  io = mempool_alloc(io_job_mempool, GFP_NOIO);
	  io->dmg = dmg;
	  wake_gc(io);
	}
        atomic_set(&dmg->gc_work_scheduled_by_timer, 0);
}

/* this executes in irq context; can't mempool_alloc w/ the GFP_NOIO
 * flag */
static enum hrtimer_restart fire_gc_timer(struct hrtimer *timer)
{
        struct dm_gecko *dmg = container_of(timer, struct dm_gecko, timer);

        if (!atomic_read(&dmg->timer_active)) {
                return HRTIMER_NORESTART;
        }
        if (atomic_cmpxchg(&dmg->gc_work_scheduled_by_timer, 0, 1) == 0) {
                queue_work(gecko_wqueue, &dmg->gc_work);
        }
        hrtimer_forward_now(timer, dmg->timer_delay);
        return HRTIMER_RESTART;
}

// TODO(tudorm): make this work for raid1 with # of stripes > 2
// and DM_GECKO_INDEPENDENT_GC / DM_GECKO_READ_TPUT;
static int default_read_stripe_for_layout(enum dm_gecko_layout layout) {
  int stripe = 0;
  switch(layout) {
  case linear:
  case raid0:
  case raid1:
          stripe = 0;
          break;
  case raid5:
  case raid6:
  default:
          printk(DM_GECKO_PREFIX "unimplemented layout\n");
          BUG_ON(1);
          break;
  }
  return stripe;
}

static int default_gc_stripe_for_layout(enum dm_gecko_layout layout) {
  int stripe = 0;
  switch(layout) {
  case linear:
  case raid0:
          stripe = 0;
          break;
  case raid1:
          stripe = 1;
          break;
  case raid5:
  case raid6:
  default:
          printk(DM_GECKO_PREFIX "unimplemented layout\n");
          BUG_ON(1);
          break;
  }
  return stripe;
}

static inline int choose_load_balanced_stripe(struct dm_gecko *dmg)
{
        /* load balance using the per-CPU counter for READs =>
         * sloppy counter */
        unsigned long long sloppy_read_cnt;
        get_cpu();
        /* can't just use reads, must also use the gc events,
         * otherwise, after a period of inactivity, when only
         * the gc runs, the sloppy_read_cnt remains the same,
         * thus all gc read requests will hit the same disk */
        sloppy_read_cnt = (this_cpu_ptr(dmg->stats))->reads +
                this_cpu_ptr(dmg->stats)->gc;
        put_cpu();
        return do_div(sloppy_read_cnt, dmg->disk_map.stripes);
}

static int choose_read_stripe(sector_t sector, struct dm_gecko *dmg)
{
        int stripe = default_read_stripe_for_layout(dmg->disk_map.layout);
        if (sector_in_seg(sector, dmg->head_seg)) {
                return choose_load_balanced_stripe(dmg);
        } else if (sector_in_seg(sector, dmg->tail_seg) &&
                   test_bit(DM_GECKO_INDEPENDENT_GC, &dmg->flags)) {
                return stripe;
        }
        // fall through
        if (test_bit(DM_GECKO_READ_TPUT, &dmg->flags)) {
                return choose_load_balanced_stripe(dmg);
        } else {
                return stripe;
        }
}

static int choose_gc_stripe(sector_t sector, struct dm_gecko *dmg)
{
        if (sector_in_seg(sector, dmg->head_seg)) {
                return choose_load_balanced_stripe(dmg);
        } else if (test_bit(DM_GECKO_INDEPENDENT_GC, &dmg->flags)) {
                // TODO(tudorm): BUG_ON if not on the tail segment.
                return default_gc_stripe_for_layout(dmg->disk_map.layout);
        } else {
                if (test_bit(DM_GECKO_READ_TPUT, &dmg->flags)) {
                        return choose_load_balanced_stripe(dmg);
                } else {
                        // yes, READ stripe!
                        return default_read_stripe_for_layout(
                                dmg->disk_map.layout);
                }
        }
}

// straced hdparm and used the following symbols from its source
#define SG_ATA_16             0x85
#define SG_ATA_16_LEN         16
#define ATA_USING_LBA         (1 << 6)
#define ATA_OP_SLEEPNOW1      0xe6
#define ATA_OP_SLEEPNOW2      0x99
#define ATA_OP_STANDBYNOW1    0xe0
#define ATA_OP_STANDBYNOW2    0x94
#define ATA_OP_SETIDLE        0xe3
#define SG_ATA_PROTO_NON_DATA (3 << 1)
#define SG_CDB2_CHECK_COND    (1 << 5)

static void prep_SG_ATA_cmd_block(unsigned char *cmd_block,
                                  enum seg_power_state pow_state)
{
        BUG_ON(pow_state == unspecified);
        cmd_block[0] = SG_ATA_16;
        cmd_block[1] = SG_ATA_PROTO_NON_DATA;
        cmd_block[2] = SG_CDB2_CHECK_COND;
        cmd_block[13] = ATA_USING_LBA;
        switch (pow_state) {
        case active:
                cmd_block[6] = 0;        // set the delay to 0
                cmd_block[14] = ATA_OP_SETIDLE;
                break;
        case standby:
                cmd_block[14] = ATA_OP_STANDBYNOW1;
                break;
        case sleep:
                cmd_block[14] = ATA_OP_SLEEPNOW1;
                break;
        default:
                BUG_ON(1);
        }
}

/* Put device into active, standby, or sleep mode. If the device is
 * put into lowest power sleep mode, it will be shut down
 * completely. A reset is required before the drive can be accessed
 * again, and the Linux IDE driver should automatically issue the
 * reset on demand (tested on a 2.6.35 kernel and it does indeed
 * automatically issue the reset). */
static void set_drive_power(struct block_device *bdev,
                            enum seg_power_state pow_state)
{
        mm_segment_t old_fs = get_fs();
        struct gendisk *disk = bdev->bd_disk;
        struct sg_io_hdr hdr;
        unsigned char sense_b[32];
        unsigned char cmd_block[SG_ATA_16_LEN];
        int err;

        memset(&hdr, 0, sizeof(hdr));
        memset(&sense_b, 0, sizeof(sense_b));
        memset(cmd_block, 0, sizeof(cmd_block));
        prep_SG_ATA_cmd_block((unsigned char *)&cmd_block, pow_state);

        hdr.interface_id = SG_INTERFACE_ID_ORIG;
        hdr.dxfer_direction = SG_DXFER_NONE;
        hdr.cmd_len = sizeof(cmd_block);
        hdr.mx_sb_len = sizeof(sense_b);
        hdr.sbp = sense_b;
        hdr.cmdp = cmd_block;
        hdr.timeout = 10000;        // timeout in milliseconds

        set_fs(KERNEL_DS);
        err = blkdev_ioctl(bdev, 0, SG_IO, (unsigned long)&hdr);
        if (err) {
                printk(DM_GECKO_PREFIX "sg_io error %d on %s\n", err,
                       disk->disk_name);
        } else {
                printk(DM_GECKO_PREFIX
                       "set /dev/%s drive power state to %s\n",
                       disk->disk_name,
                       pow_state ==
                       active ? "active" : ((pow_state == standby) ?
                                            "standby" : "sleep"));
        }
        set_fs(old_fs);
}

static void run_dm_dev_seg(struct work_struct *work)
{
        struct dm_dev_seg *seg = container_of(work, struct dm_dev_seg, work);
        struct dm_gecko *dmg = seg->ctxt;

        if (dmg->disk_map.layout != raid1 ||
            seg->next_pow_state == seg->cur_pow_state ||
            test_bit(DM_GECKO_READ_TPUT, &dmg->flags) ||
            seg == dmg->head_seg ||
            (seg == dmg->tail_seg &&
            test_bit(DM_GECKO_INDEPENDENT_GC, &dmg->flags))) {
                goto out_reset_next_pow_state;
        }

        if (seg->next_pow_state == standby || seg->next_pow_state == sleep) {
                int i, err;
                for (i = 0; i < dmg->disk_map.stripes; i++) {
                /* blocking flush while on workqueue's task context,
                 * hence will block deferred IO or gc events scheduled
                 * on same workqueue. This flush is not necessary
                 * if this was called as a result of tail advancing. */
                        err = blkdev_issue_flush(seg->dev[i]->bdev, GFP_KERNEL,
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 36)
                                                 NULL, BLKDEV_IFL_WAIT);
#else
                                                 NULL);
#endif
                        if (err) {
                                printk(DM_GECKO_PREFIX "disk flush failed "
                                       "with status %d\n", err);
                        }
                        if (i != default_read_stripe_for_layout(
                                dmg->disk_map.layout)) {
                                set_drive_power(seg->dev[i]->bdev,
                                                seg->next_pow_state);
                        }
                }
                seg->cur_pow_state = seg->next_pow_state;
        }
out_reset_next_pow_state:
        seg->next_pow_state = unspecified;
}

static int store_dm_gecko(struct dm_gecko *dmg);

static void do_sync_metadata(struct dm_gecko *dmg)
{
        unsigned long saved_flags;
        int err = 0;

        BUG_ON(in_interrupt());

	// Optimization that does not allow two (non-final)
	// metadata-sync operations to proceed at roughly the same
	// time.
        if (test_and_set_bit(DM_GECKO_SYNCING_METADATA, &dmg->flags)) {
                printk(DM_GECKO_PREFIX "A metadata-sync operation is already "
                       "in progress.\n");
		return;
	}

        down_write(&dmg->metadata_sync_sema);
	saved_flags = dmg->flags;
        // No more new IOs are being submitted from this point on.
        if (test_bit(DM_GECKO_FINAL_SYNC_METADATA, &dmg->flags)) {
                printk(DM_GECKO_PREFIX "Should not be able to issue a "
                       "metadata-sync operation after target destroy.\n");
                BUG_ON(true);
        }
        // Turn off the gc.
        set_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags);
        // Turn off the (gc) timer.
        atomic_set(&dmg->timer_active, 0);
        hrtimer_cancel(&dmg->timer);
        // Wait for all pending io jobs (including gc jobs) to finish.
        wait_event(dmg->jobs_pending_waitqueue, !atomic_read(&dmg->total_jobs));

        err = store_dm_gecko(dmg);
        if (err) {
                printk(DM_GECKO_PREFIX "Unable to store gecko metadata\n");
                goto out;
        }
        dmg->persistent_tail = dmg->tail;
        dmg->persistent_available_blocks = dmg->available_blocks;

out:
        dmg->flags = saved_flags;  // Restore other flags.
	clear_bit(DM_GECKO_SYNCING_METADATA, &dmg->flags);
        up_write(&dmg->metadata_sync_sema);
}

static void sync_metadata(struct work_struct *work)
{
        struct dm_gecko *dmg = container_of(work,
                                            struct dm_gecko,
                                            sync_metadata_work);
        do_sync_metadata(dmg);
}

static void run_deferred_jobs(struct work_struct *unused_work_struct)
{
        unsigned long flags;
        struct deferred_stats *def_stats;

        BUG_ON(in_interrupt());

        spin_lock_irqsave(&jobs_lock, flags);
        /* preemption disabled under spinlock */
        def_stats = &__get_cpu_var(deferred_stats);
        while (!list_empty(&deferred_jobs)) {
                struct io_job *io =
                    container_of(deferred_jobs.next, struct io_job, list);
                list_del(&io->list);
                --def_stats->total;

                if (io_job_is_gc(io)) {
                        ++def_stats->gc;
                        spin_unlock_irqrestore(&jobs_lock, flags);
                        BUG_ON(!io_job_is_deferred(io));
                        do_run_gc(io);
                } else {
                        ++def_stats->rw;
                        spin_unlock_irqrestore(&jobs_lock, flags);
                        BUG_ON(!io_job_is_deferred(io));
                        map_rw_io_job(io);
                }
                spin_lock_irqsave(&jobs_lock, flags);
		// May have migrated CPUs so grab a fresh reference.
		def_stats = &__get_cpu_var(deferred_stats);
        }
        spin_unlock_irqrestore(&jobs_lock, flags);
}

/* operation on hash table */
static struct io_for_block *get_io_for_block(struct dm_gecko *dmg,
                                             sector_t key)
{
        struct io_for_block *io4b;

        unsigned long bucket_idx = hash_long(key, HASH_TABLE_BITS);
        struct list_head *bucket = &dmg->buckets[bucket_idx];

        list_for_each_entry(io4b, bucket, hashtable) {
                if (io4b->key == key) {
                          return io4b;
                }
        }
        return NULL;
}

/* WARNING: duplicates are not checked for, you have been advised,
 * play nice */
static void put_io_for_block(struct dm_gecko *dmg, u32 key,
                             struct io_for_block *io4b)
{
        unsigned long bucket_idx = hash_long(key, HASH_TABLE_BITS);
        struct list_head *bucket = &dmg->buckets[bucket_idx];

        io4b->key = key;
        list_add_tail(&io4b->hashtable, bucket);
        ++dmg->htable_size;
}

static void wake_up_free_space_available(struct dm_gecko *dmg)
{
        unsigned long flags;
        spin_lock_irqsave(&dmg->lock, flags);
        __wake_up_locked(&dmg->no_free_space_waitqueue, TASK_NORMAL);
        spin_unlock_irqrestore(&dmg->lock, flags);
}

static inline u32 __relocatable_blocks(struct dm_gecko *dmg)
{
        return dmg->free_blocks - dmg->available_blocks;
}

static inline u32 __unavailable_blocks(struct dm_gecko *dmg)
{
        return dmg->size - dmg->available_blocks;
}

static inline u32 __used_blocks(struct dm_gecko *dmg)
{
        return dmg->size - dmg->free_blocks;
}

/* Should probably encode this in a proper DFA */
/* ->lock must be held */
static int __gc_needs_to_run(struct dm_gecko *dmg)
{
        /* TODO: check how many available and free blocks there are,
         * and their ratio use a bunch of watermarks, e.g. when <= 10%
         * contiguous available space, and start the gc. When the
         * reserved block percentage is hit (say 5%) then block the
         * writers. Make sure the gc can continue to make progress */

        //u32 used_blocks = __used_blocks(dmg);
        //u32 unavailable_blocks = __unavailable_blocks(dmg);
        u32 max_relocatable_blocks = __relocatable_blocks(dmg);

#ifdef ALWAYS_RUN_GC
        return (max_relocatable_blocks != 0);
#endif

	if (dmg->gc_req_in_progress >= dmg->max_gc_req_in_progress) {
                return 0;
	}

        if (test_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags)) {
                return 0;
        }
        /* Return `no need to run gc' early if:
         *      - there are no gaps / holes
         *      - there are no more concurrent gc requests allowed */
        if (max_relocatable_blocks == 0) {
                clear_bit(DM_GECKO_GC_STARTED, &dmg->flags);
                return 0;
        }

        if (test_bit(DM_GECKO_GC_STARTED, &dmg->flags)) {
                if (max_relocatable_blocks <= dmg->gc_ctrl.low_watermark) {
                        clear_bit(DM_GECKO_GC_STARTED, &dmg->flags);
                        return 0;
                } else {
                        return 1;
                }
        } else {
                if (max_relocatable_blocks >= dmg->gc_ctrl.high_watermark) {
                        set_bit(DM_GECKO_GC_STARTED, &dmg->flags);
                        return 1;
                } else {
                        return 0;
                }
        }
}

// the function may be called from irq context, so can't block
static void sched_delayed_power_adjustment_for_segment(struct dm_dev_seg
                                                       *seg,
                                                       enum seg_power_state
                                                       next_pow_state)
{
        struct dm_gecko *dmg = seg->ctxt;
        if (seg == dmg->head_seg || dmg->disk_map.layout != raid1 ||
            (seg == dmg->tail_seg &&
            test_bit(DM_GECKO_INDEPENDENT_GC, &dmg->flags))) {
                return;
        }
        seg->next_pow_state = next_pow_state;
        queue_work(gecko_wqueue, &seg->work);
}

/* Allocate/claim the next contiguously available block for writing or
   gc.  Do not need to check if the circular ring is full, since
   ->available_blocks is consistently updated and it indicates how
   many slots are available */
static  u32 __claim_next_free_block(struct dm_gecko *dmg)
{
        u32 head = dmg->head;
        BUG_ON(!is_block_marked_free(dmg->r_map[head], dmg));
        if ((++dmg->head) == dmg->size) {
                dmg->head = 0;
                ++dmg->head_wrap_around;
        }
        --dmg->persistent_available_blocks;
        --dmg->available_blocks;
        --dmg->free_blocks;
        return head;
}

/* ->lock must be held */
static u32 __ffwd_tail(struct dm_gecko *dmg)
{
        u32 cnt;
        for (cnt = 0; dmg->tail != dmg->head; ++cnt) {
                if (!is_block_marked_free(dmg->r_map[dmg->tail], dmg)) {
                        break;
                }
                /* can fast forward the tail one slot worth */
                if ((++dmg->tail) == dmg->size) {
                        dmg->tail = 0;
                        ++dmg->tail_wrap_around;
                }
                ++dmg->available_blocks;
        }
        return cnt;
}

/* ->lock must be held */
static void __relocate_gc_written_block(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;
        u32 old_l_block = dmg->d_map[io->v_block];

        BUG_ON(dmg->r_map[old_l_block] != io->v_block);
        BUG_ON(dmg->r_map[io->l_block] != io->v_block);

        dmg->r_map[old_l_block] = mark_block_free(dmg);
        ++dmg->free_blocks;
        dmg->d_map[io->v_block] = io->l_block;
}

/* ->lock must be held */
static void __relocate_written_block(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;

        BUG_ON(dmg->r_map[io->l_block] != io->v_block);
        // Since the lock is held while calling this function, the
        // block indexed by io->v_block may be in one of two states
        // only. It may either be marked free, or it may point to a
        // linear block in the reverse map that correctly holds the
        // back link, irrespective of the fact that reads and writes
        // are issued concurrently.
        if (!is_block_marked_free(dmg->d_map[io->v_block], dmg)) {
                u32 old_l_block = dmg->d_map[io->v_block];
                BUG_ON(dmg->r_map[old_l_block] != io->v_block);
                dmg->r_map[old_l_block] = mark_block_free(dmg);
                ++dmg->free_blocks;
        }
        dmg->d_map[io->v_block] = io->l_block;
}

/* lock must be held */
static struct dm_dev_seg *__touch_new_head_seg(struct dm_gecko *dmg, u32 sector)
{
        struct dm_dev_seg *ret = NULL;
        struct dm_dev_seg *seg = seg_for_sector(dmg, block_to_sector(sector));
        int is_last_write = atomic_dec_and_test(&seg->pending_writes);

        if (seg != dmg->head_seg && is_last_write) {
                struct dm_dev_seg *head_seg = dmg->head_seg;
                BUG_ON(seg->access_seq_in_log == head_seg->access_seq_in_log);
                if (seg->access_seq_in_log < head_seg->access_seq_in_log) {
                        seg->access_seq_in_log =
                            head_seg->access_seq_in_log + 1;
                        dmg->head_seg = seg;
                        ret = head_seg;
                }
        }
        return ret;
}

static void gc_complete_callback(int read_err, unsigned long write_err,
                                 void *ctxt)
{
        struct io_job *io = (struct io_job *)ctxt;
        struct io_for_block *io4b = io->parent;
        /* hold the reference, io_job may be released early */
        struct dm_gecko *dmg = io->dmg;
        unsigned long flags;
        struct dm_dev_seg *seg = NULL, *old_tail_seg = NULL;
        int keep_running = 0, freed_blocks = 0;

        /* TODO: if kcopyd fails, handle the errors as in the IO
         * completion */
        BUG_ON(read_err || write_err);

        spin_lock_irqsave(&dmg->lock, flags);

        __relocate_gc_written_block(io);
        seg = __touch_new_head_seg(dmg, io->l_block);
        freed_blocks = __ffwd_tail(dmg);  // always after __relocate
        if (freed_blocks) {
                struct dm_dev_seg *tail_seg = seg_for_sector(dmg,
                        block_to_sector(dmg->tail));
                if (tail_seg != dmg->tail_seg) {
                        old_tail_seg = dmg->tail_seg;
                        dmg->tail_seg = tail_seg;
                }
        }
        keep_running = __gc_needs_to_run(dmg);

        list_del(&io->list);
        BUG_ON(io4b->rw_cnt >= 0 || (!list_empty(&io4b->pending_io)));

        list_del(&io4b->hashtable);
        --dmg->htable_size;
        --dmg->gc_req_in_progress;

        spin_unlock_irqrestore(&dmg->lock, flags);

        if (!list_empty(&io4b->deferred_io)) {
                struct io_job *rw_io_job, *tmp;
                struct deferred_stats *def_stats;

                spin_lock_irqsave(&jobs_lock, flags);
                def_stats = &__get_cpu_var(deferred_stats);
                list_for_each_entry_safe(rw_io_job, tmp,
                                         &io4b->deferred_io, list) {
                        list_del(&rw_io_job->list);
                        __add_deferred_io_job(rw_io_job);
                        ++def_stats->total;
                }
                spin_unlock_irqrestore(&jobs_lock, flags);
                wake_deferred_wqueue();
        }

        mempool_free(io4b, io_for_block_mempool);
        if (keep_running) {
                struct dm_gecko_stats *stats;
                get_cpu();
                stats = this_cpu_ptr(dmg->stats);
                ++stats->gc_recycle;
                put_cpu();
                /* recycle the io_job, be very careful since may be
                 * in_interrupt() */
                wake_gc(io);
        } else {
                mempool_free(io, io_job_mempool);
                wake_up_free_space_available(dmg);
                do_complete_generic(dmg);
        }
        if (seg != NULL) {
                /* seg holds the reference to the old segment */
                printk(DM_GECKO_PREFIX
                       "transitioning from old seg: %d:%llu to: %d:%llu "
                       "(gc_complete)\n", seg->idx, seg->access_seq_in_log,
                       dmg->head_seg->idx, dmg->head_seg->access_seq_in_log);
                sched_delayed_power_adjustment_for_segment(seg,
                                                           dmg->low_pow_state);
        }
        if (freed_blocks > 0) {
          wake_up_free_space_available(dmg);
        }
        if (old_tail_seg != NULL) {
                printk(DM_GECKO_PREFIX "tail segment transition from : %d "
                       "to %d\n", old_tail_seg->idx, dmg->tail_seg->idx);
                sched_delayed_power_adjustment_for_segment(old_tail_seg,
                                                           dmg->low_pow_state);
        }
}

/* Cannot be called from interrupt context */
void gc_complete_read_noirq(int *dst_count,
                            struct dm_io_region *dst,
                            void *context) {
        struct io_job *io = (struct io_job *) context;
        struct dm_gecko *dmg = io->dmg;
        unsigned long flags;
        struct dm_dev_seg* seg;

        BUG_ON(in_interrupt());
        BUG_ON(*dst_count > 0);
        BUG_ON(!is_block_marked_free(io->l_block, dmg));

        spin_lock_irqsave(&dmg->lock, flags);

        if (__no_available_blocks_hard(dmg)) {
                printk(DM_GECKO_PREFIX "ran out of space.\n");
                BUG_ON(1);
        }
        io->l_block = __claim_next_free_block(dmg);
        dmg->r_map[io->l_block] = io->v_block;

        seg = linear_to_phy_all(dmg, block_to_sector(io->l_block), dst,
                                dst_count);

        atomic_inc(&seg->pending_writes);
        /* TODO: if l_block on next seg, anticipate and power-up */

        spin_unlock_irqrestore(&dmg->lock, flags);
}

static void dm_dispatch_io_gc(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;
        struct dm_io_region src;
        sector_t src_l_block, sector;

        /* Need NOT synchonize access to the phy maps. Further, I can
           access the block map !!! to fetch the entry at index
           io->v_block since the hashtable was syncronously updated to
           indicate the gc is scheduled to run on that block and there
           are no concurrent operations on the same block while it is
           relocated by gc. This means that any further operations
           will not touch said block and therefore will not alter the
           map entry at index io->v_block. Be aware that this is NOT
           the case for dm_dispatch_io_bio, since regular reads and
           writes may be issued concurrently. */
        src_l_block = dmg->d_map[io->v_block];
        BUG_ON(dmg->r_map[src_l_block] != io->v_block);
        BUG_ON(!is_block_marked_free(io->l_block, dmg));

        sector = block_to_sector(src_l_block);
        linear_to_phy_which(dmg, sector, choose_gc_stripe(sector, dmg), &src);

        DPRINTK("Relocating [block:cnt(device-major:device-minor)] "
                "%llu:%llu(%u:%u)\n",
                (unsigned long long)sector_to_block(src.sector),
                (unsigned long long)sector_to_block(src.count),
                MAJOR(src.bdev->bd_dev), MINOR(src.bdev->bd_dev));

        dmg_kcopyd_copy(
            io->dmg->kcopyd_client, &src, 0, NULL, 0,
            (dmg_kcopyd_notify_fn) gc_complete_callback, (void *) io,
            NULL,
            (dmg_kcopyd_notify_readdone_fn_noirq) gc_complete_read_noirq);
}

static void do_run_gc(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;
        struct dm_gecko_stats *stats;
        unsigned long flags;
        u32 relocated_block;
        int dispatch_io_now = 1, freed_blocks = 0;
        struct io_for_block *io4b, *extant_io4b;

        BUG_ON(in_interrupt());
        BUG_ON(!io_job_is_gc(io));

        io4b = mempool_alloc(io_for_block_mempool, GFP_NOIO);
        io4b->rw_cnt = -1;
        INIT_LIST_HEAD(&io4b->pending_io);
        INIT_LIST_HEAD(&io4b->deferred_io);
        io->parent = io4b;
        io->l_block = 0;  /* must be marked free before dispatching gc */
        list_add_tail(&io->list, &io4b->pending_io);

        spin_lock_irqsave(&dmg->lock, flags);
        /* preemption is disabled under spinlock */
        stats = this_cpu_ptr(dmg->stats);
        freed_blocks = __ffwd_tail(dmg);

        if (is_block_marked_free(dmg->r_map[dmg->tail], dmg)) {
                BUG_ON(dmg->head != dmg->tail);
                goto out_no_need_to_run;
        }

        if (!__gc_needs_to_run(dmg)) {
out_no_need_to_run:
                spin_unlock_irqrestore(&dmg->lock, flags);
                mempool_free(io, io_job_mempool);
                mempool_free(io4b, io_for_block_mempool);
                do_complete_generic(dmg);
                goto out_free_blocks;
        }

        relocated_block = dmg->tail;
        io->v_block = dmg->r_map[relocated_block];
        BUG_ON(is_block_free_or_invalid(io->v_block, dmg));
        BUG_ON(dmg->d_map[io->v_block] != relocated_block);

gc_next_relocated_block:
        extant_io4b = get_io_for_block(dmg, io->v_block);
        if (!extant_io4b) {
                put_io_for_block(dmg, io->v_block, io4b);
                io4b = NULL;        /* prevent deallocation */
                io->l_block = mark_block_free(dmg);
                ++stats->gc;
                ++dmg->gc_req_in_progress;
        } else {
                /* there is IO or gc activity in progress on this
                 * block */
                BUG_ON(list_empty(&extant_io4b->pending_io));
                /* there are pending IOs and the gc was not yet
                 * deferred on this block */
                if (extant_io4b->rw_cnt > 0
                    && list_empty(&extant_io4b->deferred_io)) {
                        ++stats->gc_rw_clash;
                        list_add_tail(&io->list, &extant_io4b->deferred_io);
                        io->parent = extant_io4b;
                } else {
                        /* the gc is already running or was already
                         * deferred on this block */
                        BUG_ON(extant_io4b->rw_cnt == 0);
                        ++stats->gc_clash;
                        /* must fast forward until the next non-free
                         * block is found */
                        while (relocated_block != dmg->head) {
                                if ((++relocated_block) == dmg->size) {
                                        /* wrap around */
                                        relocated_block = 0;
                                }
                                io->v_block = dmg->r_map[relocated_block];
                                if (!is_block_marked_free(io->v_block, dmg)) {
                                        BUG_ON(io->parent != io4b);
                                        goto gc_next_relocated_block;
                                }
                        }
                        io->parent = NULL;
                }
                /* must be set here, after the above goto */
                dispatch_io_now = 0;
        }
        spin_unlock_irqrestore(&dmg->lock, flags);

        if (io->parent == NULL) {
                mempool_free(io, io_job_mempool);
                do_complete_generic(dmg);
        }
        if (io4b != NULL) {
                mempool_free(io4b, io_for_block_mempool);
        }
        if (dispatch_io_now) {
                dm_dispatch_io_gc(io);
        }
out_free_blocks:
        if (freed_blocks > 0) {
                wake_up_free_space_available(dmg);
        }
}

static void memcpy_bio_into_page(struct io_job *io)
{
        int i;
        struct bio_vec *bvec;
        struct bio *bio = io->bio;
        char *addr =
            io->page + to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
        bio_for_each_segment(bvec, bio, i) {
                unsigned long flags;
                /* I wonder if I can use page_address(->bv_page) +
                 * ->bv_offset instead of kmaps. */
                char *bio_addr = bvec_kmap_irq(bvec, &flags);
                memcpy(addr, bio_addr, bvec->bv_len);
                bvec_kunmap_irq(bio_addr, &flags);
                addr += bvec->bv_len;
        }
}

static void memcpy_page_into_bio(struct io_job *io)
{
        int i;
        struct bio_vec *bvec;
        struct bio *bio = io->bio;
        char *addr =
            io->page + to_bytes(bio->bi_sector & GECKO_SECTOR_TO_BLOCK_MASK);
        bio_for_each_segment(bvec, bio, i) {
                unsigned long flags;
                char *bio_addr = bvec_kmap_irq(bvec, &flags);
                memcpy(bio_addr, addr, bvec->bv_len);
                bvec_kunmap_irq(bio_addr, &flags);
                addr += bvec->bv_len;
        }
}

static void io_complete_callback(unsigned long err, void *context)
{
        struct io_job *io = (struct io_job *)context;
        struct dm_gecko *dmg = io->dmg;
        struct dm_gecko_stats *stats;
        struct dm_dev_seg *seg = NULL;
        struct io_for_block *io4b = io->parent;
        int is_last_io = 0, freed_blocks = 0, run_gc = 0;
        int read_modify_write = 0;
        unsigned long flags;

        spin_lock_irqsave(&dmg->lock, flags);
        /* preemption is disabled under spinlock */
        stats = this_cpu_ptr(dmg->stats);
        BUG_ON(io4b->rw_cnt <= 0);
        if (err) {
                if (io->rw == READ) {
                        zero_fill_bio(io->bio);
                        DPRINTK("read error, returning 0s");
                        ++stats->read_err;
                } else {
                        ++stats->write_err;
                        // TODO: perhaps keep the older block instead
                        __relocate_written_block(io);
                }
        } else {
                if (io->rw == WRITE) {
                        __relocate_written_block(io);
                        seg = __touch_new_head_seg(dmg, io->l_block);
                        freed_blocks = __ffwd_tail(dmg);  // after _relocate
                        run_gc = __gc_needs_to_run(dmg);
#ifdef DROP_WRITE_WRITE_CLASH_OPTIMIZATION
                        clear_bit(WRITE_CLASH_IO_FOR_BLOCK, &io4b->flags);
#endif
                }
        }
        list_del(&io->list);        /* deleted from io4b->pending_io */
        if ((--io4b->rw_cnt) == 0) {
                BUG_ON(!list_empty(&io4b->pending_io));
                list_del(&io4b->hashtable);
                --dmg->htable_size;
                is_last_io = 1;
        }
        spin_unlock_irqrestore(&dmg->lock, flags);

        if (io->page != NULL) {
                if (err) {
                        free_page((unsigned long)io->page);
                        io->page = NULL;
                } else {
                        if (io->rw == READ && bio_data_dir(io->bio) == WRITE) {
                                memcpy_bio_into_page(io);
                                io->rw = WRITE;
                                /* resubmit IO (read-modify-write) */
                                queue_deferred_io_job(io);
                                read_modify_write = 1;
                        } else {
                                if (bio_data_dir(io->bio) == READ) {
                                        memcpy_page_into_bio(io);
                                }
                                free_page((unsigned long)io->page);
                                io->page = NULL;
                        }
                }
        }
        if (is_last_io) {
                if (!list_empty(&io4b->deferred_io)) {
                        struct io_job *io_gc =
                            list_entry(io4b->deferred_io.next,
                                       struct io_job, list);
                        list_del(&io_gc->list);
                        set_io_job_deferred(io_gc);
                        /* `there can be only one' deferred gc job per
                         * block */
                        BUG_ON((!list_empty(&io4b->deferred_io))
                               || (!io_job_is_gc(io_gc)));
                        queue_deferred_io_job(io_gc);
                }
                mempool_free(io4b, io_for_block_mempool);
        }

        if (seg != NULL) {
                /* seg holds the reference to the old segment. Call
                 * before bio_endio notifies upper layer that the
                 * operation has completed, to ensure that the flush
                 * semaphore is taken so that subsequent explicit
                 * flush requests (should they happen at such an
                 * inopportune time) are serialized w.r.t. the flush
                 * that is issued when writes advanced to a new
                 * segment. */
                printk(DM_GECKO_PREFIX
                       "transitioning from old seg: %d:%llu to: %d:%llu "
                       "(io_complete)\n", seg->idx, seg->access_seq_in_log,
                       dmg->head_seg->idx, dmg->head_seg->access_seq_in_log);
                sched_delayed_power_adjustment_for_segment(seg,
                                                           dmg->low_pow_state);
        }
        if (!read_modify_write) {
                bio_endio(io->bio, err);
                if (freed_blocks > 0) {
                        wake_up_free_space_available(dmg);
                }
                if (run_gc) {
                        wake_gc(io); /* recycle the struct io_job */
                } else {
                        mempool_free(io, io_job_mempool);
                        do_complete_generic(dmg);
                }
        }
}

/* WARNING: do NOT touch any of the shared state (e.g. the direct and
 * reverse relocation maps) from this function---accessing the members
 * of the io_job passed in is safe, e.g. io->v_block or
 * io->l_block. The context (parameter passed to the callback) is the
 * io_job. */
static int dm_dispatch_io_bio(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;
        struct dm_io_request iorq;
        struct dm_io_region where[DM_GECKO_MAX_STRIPES];
        struct bio *bio = io->bio;
        sector_t sector;
        int num_regions = 1;
        int flags;

        /* The physical map requires no synchronization since it is
         * initialized once and not altered henceforth. Further, the
         * dm_io_region(s) can be allocated on-stack even though the
         * dm_io is asynchronous since it is used to set the fields of
         * a newly allocated bio (which is itself submitted for io
         * through the submit_bio() interface). WARNING! do not touch
         * the virtual and linear maps since reads and writes may be
         * issued concurrently (that's the contract at the
         * block-level---request ordering is not ensured. */

        // the sector is the same for both READ and WRITE
        sector = block_to_sector(io->l_block);
        if (io->rw == READ) {
                num_regions = 1;
                linear_to_phy_which(dmg, sector,
                                    choose_read_stripe(sector, dmg), where);
                DPRINTK("READ <dev %u:%u> sector: %llu count: %llu",
                        MAJOR(where[0].bdev->bd_dev),
                        MINOR(where[0].bdev->bd_dev),
                        (unsigned long long)where[0].sector,
                        (unsigned long long)where[0].count);
        } else {
                linear_to_phy_all(dmg, sector, where, &num_regions);
                BUG_ON(num_regions > dmg->disk_map.stripes);
                DPRINTK
                    ("WRITE <dev %u:%u> sector: %llu count: %llu num_dests: %u",
                     MAJOR(where[0].bdev->bd_dev),
                     MINOR(where[0].bdev->bd_dev),
                     (unsigned long long)where[num_regions - 1].sector,
                     (unsigned long long)where[num_regions - 1].count,
                     num_regions);
        }

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
#error "Kernel version unsuported (too old)."
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28)
        flags = 0; //(1 << BIO_RW_SYNC);
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
        flags = 0; //(1 << BIO_RW_SYNCIO) | (1 << BIO_RW_UNPLUG);
#else
        flags = 0; //(1 | REQ_SYNC | REQ_UNPLUG);
#endif
        iorq.bi_rw = (io->rw | flags);

        if (io->page != NULL) {
                /* unaligned request */
                iorq.mem.type = DM_IO_KMEM;
                iorq.mem.ptr.addr = io->page;
                iorq.mem.offset = 0;  // only required for DM_IO_PAGE_LIST
        } else {
                iorq.mem.type = DM_IO_BVEC;
                iorq.mem.ptr.bvec = bio->bi_io_vec + bio->bi_idx;
        }
        iorq.notify.fn = io_complete_callback;
        iorq.notify.context = io;
        iorq.client = dmg->io_client;

        /* The beauty of the log structure is that I need not maintain
         * consistent ordering of write requests across mirrors, since
         * all writes are performed against fresh blocks and no
         * in-place modifications take place. For a conventional block
         * device, two writes may be issued concurrently (e.g.  by
         * uncooperating processes while bypassing the buffer cache w/
         * O_DIRECT) and while this may be perfectly fine for a block
         * device backed up by a single disk, it may be an issue for a
         * RAID-1 array. For example, dm_io -> async_io -> dispatch_io
         * -> do_region will call submit_bio for every mirror disk,
         * which means that concurrent requests A and B for the same
         * block X mirrored on devices D1 and D2 may be queued to the
         * respective elevators in any order (e.g. A, B for D1 and B,
         * A for D2). This means that a write-write conflict will
         * break the RAID-1.  The log structure needs not solve this
         * issue at all, since by construction, the concurrent
         * requests A and B for the same (virtual) block X will be
         * mapped down to different linear blocks, and the latter
         * request will persist correctly.
         *
         * Note that #ifdef DROP_WRITE_WRITE_CLASH_OPTIMIZATION then
         * the above write-write conflict will not even occur since if
         * concurrent writes are issued to the same block, only the
         * first will succeed. We can get away with this optimization
         * since POSIX does not guarantee any ordering of writes for
         * uncooperating processes issuing concurrent writes.
         */
        return dm_io(&iorq, num_regions, where, NULL);
}

static void map_rw_io_job(struct io_job *io)
{
        struct dm_gecko *dmg = io->dmg;
        struct dm_gecko_stats *stats;
        unsigned long flags;
        int dispatch_io_now = 1;
        struct io_for_block *io4b, *extant_io4b;

        BUG_ON(in_interrupt());
        io4b = mempool_alloc(io_for_block_mempool, GFP_NOIO);
        io4b->rw_cnt = 1;
        io4b->flags = 0;
        INIT_LIST_HEAD(&io4b->pending_io);
        INIT_LIST_HEAD(&io4b->deferred_io);
        io->parent = io4b;
        list_add_tail(&io->list, &io4b->pending_io);

        spin_lock_irqsave(&dmg->lock, flags);
        /* preemption is disabled under spinlock */
        stats = this_cpu_ptr(dmg->stats);

        BUG_ON(is_block_invalid(dmg->d_map[io->v_block], dmg));
        if (!is_block_marked_free(dmg->d_map[io->v_block], dmg)) {
                io->l_block = dmg->d_map[io->v_block];
                BUG_ON(dmg->r_map[io->l_block] != io->v_block);
        } else {
                io->l_block = mark_block_free(dmg);
        }
        if (io->rw == READ) {
                ++stats->reads;
                /* optimization: WARNING, it complicates the
                 * read-modify-write code paths */
                if (is_block_marked_free(dmg->d_map[io->v_block], dmg)) {
                        ++stats->read_empty;
                        spin_unlock_irqrestore(&dmg->lock, flags);
                        if (io->page != NULL) {
                                if (bio_data_dir(io->bio) == WRITE) {
                                        clear_page(io->page);
                                        memcpy_bio_into_page(io);
                                        io->rw = WRITE;
                                        /* resubmit IO (read-modify-write) */
                                        queue_deferred_io_job(io);
                                        return;
                                } else {
                                        free_page((unsigned long)io->page);
                                        /* and continue to fall through */
                                }
                        }
                        DPRINTK("READ unwritten blocks, returning zeroes.");
                        zero_fill_bio(io->bio);
#ifdef DROP_WRITE_WRITE_CLASH_OPTIMIZATION
out_without_submitting_io:
#endif
                        bio_endio(io->bio, 0);
                        mempool_free(io, io_job_mempool);
                        mempool_free(io4b, io_for_block_mempool);
                        do_complete_generic(dmg);
                        return;
                }
        } else {
                ++stats->writes;
        }
        extant_io4b = get_io_for_block(dmg, io->v_block);
        if (!extant_io4b) {
                put_io_for_block(dmg, io->v_block, io4b);
                io4b = NULL;        /* to prevent deallocation before ret */
        } else {
                BUG_ON(list_empty(&extant_io4b->pending_io));
                /* unchain from io4b->pending_io, unnecessary op */
                list_del(&io->list);
                io->parent = extant_io4b;

                if (extant_io4b->rw_cnt > 0) {
                        /* there is concurrent IO on this block */
#ifdef DROP_WRITE_WRITE_CLASH_OPTIMIZATION
                        if (io->rw == WRITE) {
                                if (test_and_set_bit(WRITE_CLASH_IO_FOR_BLOCK,
                                                     &io4b->flags)) {
                                        ++stats->ww_clash;
                                        spin_unlock_irqrestore(&dmg->lock,
                                                               flags);
                                        if (io->page != NULL) {
                                                free_page((unsigned long)
                                                          io->page);
                                                io->page = NULL;
                                        }
                                        goto out_without_submitting_io;
                                }
                        }
#endif
                        ++stats->rw_clash;
                        ++extant_io4b->rw_cnt;
                        list_add_tail(&io->list, &extant_io4b->pending_io);
                } else {
                        /* the gc is running on this block */
                        BUG_ON(extant_io4b->rw_cnt == 0); // or != -1
                        ++stats->rw_gc_clash;
                        dispatch_io_now = 0;
                        list_add_tail(&io->list, &extant_io4b->deferred_io);
                }
        }
        if (dispatch_io_now && io->rw == WRITE) {
               /* Unlike DEFINE_WAIT, DECLARE_WAITQUEUE uses
                * default_wake_function instead of
                * autoremove_wake_function to wake up the task. The
                * former will NOT remove the woken task from the
                * wait_queue_head_t whereas the latter will. We don't
                * want the task removed. */
                DECLARE_WAITQUEUE(__wait, current);
                if (!__no_available_blocks(dmg)) {
                        goto fastpath_claim_block_for_writing;
                }
                // If there's no available space for this WRITE
                // request, block the underlying task. Note that we
                // need not force-schedule the gc to run at this
                // point, since it most likely is already
                // running. Worse case scenario, the gc will be
                // delayed-scheduled by the timer.
                __add_wait_queue(&dmg->no_free_space_waitqueue, &__wait);
                for (;;) {
                        __set_current_state(TASK_UNINTERRUPTIBLE);

                        if (!__no_available_blocks(dmg)) {
                                break;
                        }
                        BUG_ON(in_interrupt());
                        spin_unlock_irqrestore(&dmg->lock, flags);
                        schedule();
                        // at this point, current is in TASK_RUNNING
                        spin_lock_irqsave(&dmg->lock, flags);
                }
                __set_current_state(TASK_RUNNING);
                __remove_wait_queue(&dmg->no_free_space_waitqueue, &__wait);
fastpath_claim_block_for_writing:
                io->l_block = __claim_next_free_block(dmg);
                dmg->r_map[io->l_block] = io->v_block;
                atomic_inc(&seg_for_sector(
                    dmg, block_to_sector(io->l_block))->pending_writes);
        }
        spin_unlock_irqrestore(&dmg->lock, flags);

        if (io4b != NULL) {
                mempool_free(io4b, io_for_block_mempool);
        }
        if (dispatch_io_now) {
                dm_dispatch_io_bio(io);
        }
}

static int map_rw(struct dm_gecko *dmg, struct bio *bio)
{
        struct io_job *io = mempool_alloc(io_job_mempool, GFP_NOIO);

        io->bio = bio;
        io->dmg = dmg;
        io->page = NULL;

        if (!bio_at_block_boundary(bio)) {
                struct dm_gecko_stats *stats;
                /* if not aligned at page boundary, must be less than
                 * a page worth of data */
                BUG_ON(bio->bi_size >= GECKO_BLOCK_SIZE);

                io->page = (void *)__get_free_page(GFP_NOIO);
                if (io->page == NULL) {
                        mempool_free(io, io_job_mempool);
                        bio_endio(bio, -ENOMEM);
                        goto out_ret;
                }
                get_cpu();
                stats = this_cpu_ptr(dmg->stats);
                if (bio_data_dir(bio) == READ) {
                        ++stats->subblock_reads;
                } else {
                        ++stats->subblock_writes;
                }
                put_cpu();

                io->rw = READ;  /* read-modify-update cycle, read first */

                DPRINTK("%s request unaligned, sector(%llu) : size(%llu)",
                        (bio_data_dir(bio) == READ) ? "READ" : "WRITE",
                        (unsigned long long)bio->bi_sector,
                        (unsigned long long)bio->bi_size);
        } else {
                /* if aligned at page boundary, must be single block
                 * worth of data */
                BUG_ON(bio->bi_size != GECKO_BLOCK_SIZE);
                io->rw = bio_data_dir(bio);
        }

        io->v_block = sector_to_block(bio->bi_sector);
        // the block must fit in the range
        BUG_ON(is_block_free_or_invalid(io->v_block, dmg));
        atomic_inc(&dmg->total_jobs);

        map_rw_io_job(io);
out_ret:
        return DM_MAPIO_SUBMITTED;
}

/* TRIMs are advisory, do not issue them when there are other pending
 * read/write or gc relocation/cleaning on the target block. Further,
 * they are not deferred */
static int map_discard(struct dm_gecko *dmg, struct bio *bio)
{
        unsigned long flags;
        struct dm_gecko_stats *stats;
        int freed_blocks = 0;
        sector_t v_block = sector_to_block(bio->bi_sector);

        /* never discard block 0 which holds the superblock */
        BUG_ON(v_block == 0);
        spin_lock_irqsave(&dmg->lock, flags);
        /* preemption is disabled under spinlock */
        stats = this_cpu_ptr(dmg->stats);

        if (get_io_for_block(dmg, v_block) != NULL) {
                ++stats->dropped_discards;
        } else {
                u32 l_block = dmg->d_map[v_block];

                BUG_ON(is_block_invalid(l_block, dmg));
                if (is_block_marked_free(l_block, dmg)) {
                        WARN(1, DM_GECKO_PREFIX "trim on free block!\n");
                } else {
                        BUG_ON(v_block != dmg->r_map[l_block]);

                        dmg->r_map[l_block] = mark_block_free(dmg);
                        dmg->d_map[v_block] = mark_block_free(dmg);

                        ++stats->discards;
                        ++dmg->free_blocks;
                        freed_blocks = __ffwd_tail(dmg);
                }
        }
        spin_unlock_irqrestore(&dmg->lock, flags);

        if (freed_blocks > 0) {
                wake_up_free_space_available(dmg);
        }
        /* discards are not issued since we have HDDs not SSDs */
        bio_endio(bio, 0);
        return DM_MAPIO_SUBMITTED;
}

static int gecko_map(struct dm_target *ti, struct bio *bio,
                     union map_info *map_context)
{
        struct dm_gecko *dmg = (struct dm_gecko *)ti->private;
        int ret = DM_MAPIO_REQUEUE;

        down_read(&dmg->metadata_sync_sema);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 36)
        if (bio_empty_barrier(bio)) {
#else
        if (bio->bi_rw & REQ_FLUSH) {
#endif
                struct dm_io_region where;
                struct dm_gecko_stats *stats;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
                unsigned target_req_nr = map_context->flush_request;
#else
                unsigned target_req_nr = map_context->target_request_nr;
#endif
                get_cpu();
                stats = this_cpu_ptr(dmg->stats);
                ++stats->empty_barriers;
                put_cpu();
                /* TODO: fix the case when the dmg->head just advanced
                 * across disks rendering the barrier ineffective on
                 * the indended disks. When dmg->head linear index
                 * advances to a new disk, the previous disk's mirrors
                 * are to be put in a lower power state. Currently, we
                 * issue a synchronous barrier so that all in-progress
                 * writes will complete before continuing, also fixing
                 * the case. */
		if (dmg->disk_map.layout == raid0) {
		        linear_to_phy_which(dmg,
					    block_to_sector(dmg->head) +
					    target_req_nr,
					    0, &where);
		} else {
		        linear_to_phy_which(dmg, block_to_sector(dmg->head),
					    target_req_nr, &where);
		}
                bio->bi_bdev = where.bdev;
                /* the empty barriers do not indicate which
                 * sectors:size are sync'ed */
                DPRINTK("bio_empty_barrier device(%u:%u) (%llu:%llu) (%u)",
                        MAJOR(bio->bi_bdev->bd_dev),
                        MINOR(bio->bi_bdev->bd_dev),
                        (unsigned long long)sector_to_block(bio->bi_sector),
                        (unsigned long long)to_sector(bio->bi_size),
			target_req_nr);

                ret = DM_MAPIO_REMAPPED;
                goto out;
        }
        DPRINTK("%s request for sector %llu, %u bytes",
                bio_rw(bio) == WRITE ? "WRITE" :
                (bio_rw(bio) == READA ? "READA" : "READ"),
                (unsigned long long)bio->bi_sector, bio->bi_size);

        if (bio->bi_rw & REQ_DISCARD) {
                ret = map_discard(dmg, bio);
        } else {
                ret = map_rw(dmg, bio);
        }
out:
        up_read(&dmg->metadata_sync_sema);
        return ret;
}

static void dm_gecko_put_devices(struct dm_target *ti, struct dm_gecko *dmg)
{
        struct list_head *dm_dev_segs = &dmg->disk_map.dm_dev_segs;

        while (!list_empty(dm_dev_segs)) {
                int i;
                struct dm_dev_seg *seg =
                    list_entry(dm_dev_segs->next, struct dm_dev_seg, list);

                list_del(&seg->list);
                for (i = 0; i < dmg->disk_map.stripes; i++) {
                        /* initializing the disk_map NULLifies
                         * ->dev[i] before dm_get_device */
                         if (seg->dev[i]) {
                                dm_put_device(ti, seg->dev[i]);
                         }
                }
                kfree(seg);
        }
}

/* Schedule power adjustment for all mirror stripes except for
 * ->head_seg or ->tail_seg if gc is independent from read.
 * WARNING: since the power adjustment happens asynchornously
 * on the workqueue, make sure the workqueue does not disappear
 * from right under.  */
static void sched_delayed_power_adjustment_for_segments(struct dm_gecko *dmg)
{
  struct dm_dev_seg *seg;
        if (test_bit(DM_GECKO_READ_TPUT, &dmg->flags)) {
                return;
        }
        list_for_each_entry(seg, &dmg->disk_map.dm_dev_segs, list) {
                sched_delayed_power_adjustment_for_segment(seg,
                                                           dmg->low_pow_state);
        }
}

// This function is synchronous.
static void power_up_segment(struct dm_dev_seg *seg) {
        struct dm_gecko *dmg = seg->ctxt;
        int i;
        for (i = 0; i < dmg->disk_map.stripes; i++) {
                set_drive_power(seg->dev[i]->bdev, active);
        }
}

// This function is synchronous.
static void power_up_all_segments(struct dm_gecko *dmg)
{
        struct dm_dev_seg *seg;
        list_for_each_entry(seg, &dmg->disk_map.dm_dev_segs, list) {
                power_up_segment(seg);
        }
}

static struct dm_dev_seg *seg_alloc_and_init(gfp_t flags, struct dm_gecko *dmg)
{
        struct dm_dev_seg *seg = kmalloc(sizeof(*seg), flags);
        int j;

        if (!seg) {
                return NULL;
        }
        seg->ctxt = dmg;
        seg->cur_pow_state = seg->next_pow_state = unspecified;
        seg->access_seq_in_log = 0;
        atomic_set(&seg->pending_writes, 0);
        INIT_WORK(&seg->work, run_dm_dev_seg);
        for (j = 0; j < dmg->disk_map.stripes; j++) {
                /* ensure error handing works */
                seg->dev[j] = NULL;
        }
        return seg;
}

static int load_dm_gecko(struct dm_target *ti, struct dm_gecko *dmg)
{
        struct dm_gecko_persistent_metadata *dmg_meta;
        struct dm_gecko_dev *dmg_devs;
        size_t i, map_size;
        int sz, err = 0, disk_cnt;
        struct file *file;
        loff_t pos = 0;
        mm_segment_t old_fs = get_fs();

        char *page = (char *)__get_free_page(GFP_KERNEL);
        if (!page) {
                return -ENOMEM;
        }
        set_fs(KERNEL_DS);

        file = filp_open(dmg->meta_filename, O_LARGEFILE | O_RDONLY, 0);
        if (IS_ERR(file)) {
                printk(DM_GECKO_PREFIX "open %s\n", dmg->meta_filename);
                err = PTR_ERR(file);
                goto out;
        }

        sz = vfs_read(file, page, PAGE_SIZE, &pos);
        if (sz != PAGE_SIZE) {
                err = (sz < 0) ? sz : -EIO;
                printk(DM_GECKO_PREFIX "read metadata %s: %d\n",
                       dmg->meta_filename, err);
                goto out_close;
        }

        dmg_meta = (struct dm_gecko_persistent_metadata *)page;
        if (dmg_meta->magic != DM_GECKO_META_MAGIC) {
                printk(DM_GECKO_PREFIX "magic number error, endianness?\n");
                err = -EINVAL;
                goto out_close;
        }

        dmg->incarnation = dmg_meta->incarnation + 1;
        dmg->size = dmg_meta->size;
        dmg->tail = dmg_meta->tail;
        dmg->head = dmg_meta->head;
        dmg->available_blocks = dmg_meta->available_blocks;
        dmg->free_blocks = dmg_meta->free_blocks;
        dmg->disk_map.layout = dmg_meta->layout;
        dmg->disk_map.stripes = dmg_meta->stripes;
        BUG_ON(dmg->disk_map.stripes > DM_GECKO_MAX_STRIPES);
        dmg->flags = dmg_meta->flags;
	dmg->max_gc_req_in_progress = dmg_meta->max_gc_req_in_progress;
        dmg->gc_ctrl = dmg_meta->gc_ctrl;
        dmg->low_pow_state = dmg_meta->low_pow_state;

        disk_cnt = dmg_meta->disk_map_cnt * dmg_meta->stripes;
        if (disk_cnt * sizeof(*dmg_devs) + sizeof(*dmg_meta) > PAGE_SIZE) {
                printk(DM_GECKO_PREFIX "too many disks\n");
                err = -EINVAL;
                goto out_close;
        }

        dmg_devs = (struct dm_gecko_dev *) (page + sizeof(*dmg_meta));
        INIT_LIST_HEAD(&dmg->disk_map.dm_dev_segs);
        dmg->disk_map.cnt = 0;
        dmg->disk_map.len = 0;
        for (i = 0; i < dmg_meta->disk_map_cnt; i++) {
                int j;
                sector_t stripes_len = 0;
                struct dm_dev_seg *seg = seg_alloc_and_init(GFP_KERNEL, dmg);
                if (!seg) {
                        printk(DM_GECKO_PREFIX "kmalloc dm_dev_seg\n");
                        err = -ENOMEM;
                        goto out_err_1;
                }
                seg->idx = i;
                list_add_tail(&seg->list, &dmg->disk_map.dm_dev_segs);

                for (j = 0; j < dmg_meta->stripes; j++) {
                        struct dm_gecko_dev *dmg_dev =
                            &dmg_devs[i * dmg_meta->stripes + j];
                        err = dm_get_device(ti,
                                            dmg_dev->name,
                                            dm_table_get_mode(ti->table),
                                            &seg->dev[j]);
                        if (err) {
                                printk(DM_GECKO_PREFIX
                                       "device lookup failed\n");
                                goto out_err_1;
                        }
                        if (seg->dev[0]->bdev->bd_inode->i_size !=
                            seg->dev[j]->bdev->bd_inode->i_size) {
                                printk(DM_GECKO_PREFIX
                                       "stripes must match in size "
                                       "(%llu != %llu)\n",
                                       seg->dev[0]->bdev->bd_inode->i_size,
                                       seg->dev[j]->bdev->bd_inode->i_size);
                                err = -EINVAL;
                                goto out_err_1;
                        }
                        stripes_len += seg->dev[j]->bdev->bd_inode->i_size;
                }

                seg->start = dmg->disk_map.len;
                seg->len = (dmg->disk_map.layout == raid0) ?
                    (stripes_len >> SECTOR_SHIFT) :
                    (seg->dev[0]->bdev->bd_inode->i_size >> SECTOR_SHIFT);
                dmg->disk_map.len += seg->len;

                ++dmg->disk_map.cnt;
        }
        if (dmg->disk_map.len != ti->len) {
                printk(DM_GECKO_PREFIX
                       "disk_map length != dm_target length\n");
                err = -EINVAL;
                goto out_err_1;
        }
        BUG_ON(dmg->size != sector_to_block(dmg->disk_map.len));

        /* allocate the maps */
        map_size = PAGE_ALIGN(sizeof(*dmg->d_map) * dmg->size);
        dmg->d_map = vmalloc(map_size);
        if (!dmg->d_map) {
                printk(DM_GECKO_PREFIX "vmalloc ->d_map failed\n");
                err = -ENOMEM;
                goto out_err_1;
        }
        /* same size as direct map */
        dmg->r_map = vmalloc(map_size);
        if (!dmg->r_map) {
                printk(DM_GECKO_PREFIX "vmalloc ->r_map failed\n");
                err = -ENOMEM;
                goto out_err_2;
        }

        /* read the maps (the maps are multiple of PAGE_SIZE for convenience) */
        for (i = 0; i < map_size; i += PAGE_SIZE) {
                char *dest = &((char *)dmg->d_map)[i];

                sz = vfs_read(file, dest, PAGE_SIZE, &pos);
                if (sz != PAGE_SIZE) {
                        err = (sz < 0) ? sz : -EIO;
                        printk(DM_GECKO_PREFIX "vfs_read ->d_map\n");
                        goto out_err_3;
                }
        }
        for (i = 0; i < map_size; i += PAGE_SIZE) {
                char *dest = &((char *)dmg->r_map)[i];

                sz = vfs_read(file, dest, PAGE_SIZE, &pos);
                if (sz != PAGE_SIZE) {
                        err = (sz < 0) ? sz : -EIO;
                        printk(DM_GECKO_PREFIX "vfs_read ->r_map\n");
                        goto out_err_3;
                }
        }

out_close:
        filp_close(file, current->files);
out:
        set_fs(old_fs);
        free_page((unsigned long)page);
        return err;

out_err_1:
        dm_gecko_put_devices(ti, dmg);
        goto out_close;

out_err_2:
        kfree(dmg->d_map);
        goto out_err_1;

out_err_3:
        kfree(dmg->r_map);
        goto out_err_2;
}

void create_artificial_metadata_maps(struct dm_gecko *dmg,
				     sector_t total_blocks,
				     int data_blocks,
				     int free_blocks) {
        u32 vblock = 0;
	enum fake_writing {
	        FAKE_WR_BLOCKS,
		FAKE_WR_HOLES,
	};
	enum fake_writing state = FAKE_WR_BLOCKS;  // start by writing blocks
	int blocks_written = 0;
	int holes_written = 0;
	sector_t size = dmg->tail + total_blocks;
	BUG_ON(size > 0xffffffff);
	BUG_ON(size > dmg->size);
	set_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags);  // force-stop the gc
	for (dmg->head = dmg->tail; dmg->head < size; ++dmg->head) {
	        // The entire map contains `holes'.
	        BUG_ON(dmg->r_map[dmg->head] != mark_block_free(dmg));
		switch (state) {
		case FAKE_WR_BLOCKS:
		        dmg->r_map[dmg->head] = vblock;
			dmg->d_map[vblock] = dmg->head;
			++vblock;
			--dmg->persistent_available_blocks;
			--dmg->available_blocks;
			--dmg->free_blocks;
			if (++blocks_written >= data_blocks) {
			        holes_written = 0;
				state = FAKE_WR_HOLES;
			}
			break;
		case FAKE_WR_HOLES:
		        if (++holes_written >= free_blocks) {
			        blocks_written = 0;
				state = FAKE_WR_BLOCKS;
			}
			break;
		default:
		        printk(DM_GECKO_PREFIX
			       "invalid artificial metadata map write state\n");
			BUG_ON(1);
			break;
		}
	}
}

/*
 * insmod dm-gecko_mod.ko <persistent (true=1 | false)>
 * <metadata-file> [<layout ("linear" | "raid1" | "raid0")>]
 * [<# of stripes>] <# of devices> [<dev_path>]+ ]?
 *
 * Note that a "linear" layout is equivalent to a "raid0" or a "raid1"
 * layout with a single stripe (it exists for historical reasons---the
 * first one to be developed).
 *
 * If (!persistent) then the layout, number and device paths are
 * irrelevant.  Otherwise, the metadata is persistently saved when the
 * target it destroyed.  The metadata should also be synchronized to
 * persistent storage periodically and perhaps only dirty mappings
 * should be updated (i.e. as results of reads). */
static int gecko_ctr(struct dm_target *ti, unsigned int argc, char *argv[])
{
        int err = -ENOMEM, persistent, i, dm_devs, arg = 0;
        char *end;
	u32 mapidx;

        struct dm_gecko *dmg = kmalloc(sizeof(*dmg), GFP_KERNEL);
        if (!dmg) {
                ti->error = DM_GECKO_PREFIX "unable to allocate gecko context";
                goto out1;
        }
        memset(dmg, 0, sizeof(*dmg));        /* zeros out the stats as well */
        // TODO: agree on a set of default startup flags
        set_bit(DM_GECKO_READ_TPUT, &dmg->flags);
        spin_lock_init(&dmg->lock);
        init_waitqueue_head(&dmg->jobs_pending_waitqueue);
        init_waitqueue_head(&dmg->no_free_space_waitqueue);
        init_rwsem(&dmg->metadata_sync_sema);
        atomic_set(&dmg->total_jobs, 0);
        hrtimer_init(&dmg->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
        dmg->timer.function = fire_gc_timer;
        INIT_WORK(&dmg->gc_work, try_sched_gc);
        atomic_set(&dmg->gc_work_scheduled_by_timer, 0);
        atomic_set(&dmg->timer_active, 1);
        INIT_WORK(&dmg->sync_metadata_work, sync_metadata);
        dmg->gc_req_in_progress = 0;
        dmg->max_gc_req_in_progress = GC_CONCURRENT_REQ;
        dmg->low_pow_state = DEFAULT_LOW_POW_STATE;
        dmg->incarnation = 1;

        if (!(dmg->stats = alloc_percpu(struct dm_gecko_stats))) {
                ti->error = DM_GECKO_PREFIX "unable to alloc_percpu stats";
                printk("%s\n", ti->error);
                goto out2;
        }

        err = dmg_kcopyd_client_create(DM_GECKO_GC_COPY_PAGES,
                                       &dmg->kcopyd_client);
        if (err) {
                ti->error =
                    DM_GECKO_PREFIX "unable to register as a kcopyd client";
                printk("%s\n", ti->error);
                goto out3;
        }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
        dmg->io_client = dm_io_client_create();
#else
        dmg->io_client = dm_io_client_create(DM_GECKO_GC_COPY_PAGES);
#endif
        if (IS_ERR(dmg->io_client)) {
                ti->error =
                    DM_GECKO_PREFIX "unable to register as an io client";
                err = PTR_ERR(dmg->io_client);
                printk("%s, errno=%d\n", ti->error, err);
                goto out4;
        }

        /* parse args */
        persistent = simple_strtol(argv[arg++], &end, 10);
        if (*end) {
                ti->error = DM_GECKO_PREFIX "invalid persistence arg";
                printk("%s\n", ti->error);
                err = -EINVAL;
                goto out5;
        }

        dmg->meta_filename = kstrdup(argv[arg++], GFP_KERNEL);
        if (!dmg->meta_filename) {
                ti->error = DM_GECKO_PREFIX "unable to kstrdup meta-filename";
                printk("%s\n", ti->error);
                err = -ENOMEM;
                goto out5;
        }

        if (persistent) {
                err = load_dm_gecko(ti, dmg);
                if (err) {
                        ti->error =
                            DM_GECKO_PREFIX
                            "unable to load gecko from meta-file";
                        printk("%s\n", ti->error);
                        goto out5;
                }
                goto dm_maps_ready;
        }

        if (!persistent && argc < 5) {
                ti->error = DM_GECKO_PREFIX "insufficient arguments";
                printk("%s\n", ti->error);
                err = -EINVAL;
                goto out5;
        }

        if (strcmp(argv[arg], "linear") == 0) {
                dmg->disk_map.layout = linear;
        } else if (strcmp(argv[arg], "raid1") == 0) {
                dmg->disk_map.layout = raid1;
        } else if (strcmp(argv[arg], "raid0") == 0) {
                dmg->disk_map.layout = raid0;
        } else {
                ti->error = DM_GECKO_PREFIX "invalid layout";
                printk("%s\n", ti->error);
                err = -EINVAL;
                goto out5;
        }
	++arg;
	if (dmg->disk_map.layout == raid1 || dmg->disk_map.layout == raid0) {
	        dmg->disk_map.stripes = simple_strtoul(argv[arg++], &end, 10);
		if (*end || dmg->disk_map.stripes > DM_GECKO_MAX_STRIPES) {
		        ti->error = DM_GECKO_PREFIX "invalid number of stripes";
			printk("%s\n", ti->error);
			err = -EINVAL;
			goto out5;
		}
	} else {
  	        dmg->disk_map.stripes = 1;
	}
	printk(DM_GECKO_PREFIX "# of stripes: %d\n", dmg->disk_map.stripes);
        dm_devs = simple_strtoul(argv[arg++], &end, 10);
	if (!(*end)) {
	  printk(DM_GECKO_PREFIX "# of devices: %d\n", dm_devs);
	}
        if (!dm_devs || *end || dm_devs != (argc - arg) ||
            ((dmg->disk_map.layout == raid1 || dmg->disk_map.layout == raid0) &&
	     (dm_devs % dmg->disk_map.stripes != 0))) {
                ti->error = DM_GECKO_PREFIX "invalid number of devices";
                printk("%s\n", ti->error);
                err = -EINVAL;
                goto out5;
        }

        INIT_LIST_HEAD(&dmg->disk_map.dm_dev_segs);
        dmg->disk_map.cnt = dm_devs / dmg->disk_map.stripes;
        dmg->disk_map.len = 0;
        for (i = 0; i < dmg->disk_map.cnt; i++) {
                int j;
                sector_t stripes_len = 0;

                struct dm_dev_seg *seg = seg_alloc_and_init(GFP_KERNEL, dmg);
                if (!seg) {
                        ti->error = DM_GECKO_PREFIX "kmalloc dm_dev_seg";
                        printk("%s\n", ti->error);
                        err = -ENOMEM;
                        goto out6;
                }
                seg->idx = i;
                list_add_tail(&seg->list, &dmg->disk_map.dm_dev_segs);

                for (j = 0; j < dmg->disk_map.stripes; j++) {
                        err = dm_get_device(
                            ti,
                            argv[arg + (i * dmg->disk_map.stripes + j)],
                            dm_table_get_mode(ti->table),
                            &seg->dev[j]);
                        if (err) {
                                ti->error =
                                    DM_GECKO_PREFIX "device lookup failed";
                                printk("%s\n", ti->error);
                                goto out6;
                        }

			// TODO(tudorm): take the min size
                        if (seg->dev[0]->bdev->bd_inode->i_size !=
                            seg->dev[j]->bdev->bd_inode->i_size) {
                                ti->error =
                                    DM_GECKO_PREFIX
                                    "stripes must match in size";
                                printk("%s (%llu != %llu)\n", ti->error,
                                       seg->dev[0]->bdev->bd_inode->i_size,
                                       seg->dev[j]->bdev->bd_inode->i_size);
                                err = -EINVAL;
                                goto out6;
                        }
			stripes_len += seg->dev[j]->bdev->bd_inode->i_size;
                        printk(DM_GECKO_PREFIX "added disk for stripe %d:%d\n",
                               i, j);
                }
                seg->start = dmg->disk_map.len;
                seg->len = (dmg->disk_map.layout == raid0) ?
		  (stripes_len >> SECTOR_SHIFT) :
		  (seg->dev[0]->bdev->bd_inode->i_size >> SECTOR_SHIFT);
                printk(DM_GECKO_PREFIX "sector %d start=%ld and len=%ld\n",
                        seg->idx, seg->start, seg->len);
                dmg->disk_map.len += seg->len;
        }
        if (dmg->disk_map.len != ti->len) {
                ti->error =
                    DM_GECKO_PREFIX "disk_map length != dm_target length";
                printk("%s\n", ti->error);
                err = -EINVAL;
                goto out6;
        }

	if (sector_to_block(dmg->disk_map.len) > 0xffffffff-1) {
  	        ti->error = DM_GECKO_PREFIX "unsupported size (too large)";
                printk("%s \n", ti->error);
                err = -EINVAL;
                goto out6;
	}

        /* TODO: need to round to minimal block numbers */
	dmg->size = sector_to_block(dmg->disk_map.len);
        /* (dmg->size-1) for circular buffer logic: one slot wasted to
         * distinguish between full and empty circular buffer. */
        dmg->available_blocks = dmg->free_blocks = dmg->size-1;
        dmg->gc_ctrl.low_watermark = GC_DEFAULT_LOW_WATERMARK;
        dmg->gc_ctrl.high_watermark = GC_DEFAULT_HIGH_WATERMARK;

        /* Allocate the maps, initialize them, and also initialize the
         * circular pointers. The maps are page aligned and their size
         * is also a multiple of PAGE_SIZE to simplify the potentially
         * selective writing of the metadata. */
        dmg->d_map = vmalloc(PAGE_ALIGN(sizeof(*dmg->d_map) * dmg->size));
        if (!dmg->d_map) {
                ti->error = DM_GECKO_PREFIX "vmalloc ->d_map failed";
                printk("%s\n", ti->error);
                err = -ENOMEM;
                goto out6;
        }
        dmg->r_map = vmalloc(PAGE_ALIGN(sizeof(*dmg->r_map) * dmg->size));
        if (!dmg->r_map) {
                ti->error = DM_GECKO_PREFIX "vmalloc ->r_map failed";
                printk("%s\n", ti->error);
                err = -ENOMEM;
                goto out7;
        }
        for (mapidx = 0; mapidx < dmg->size; ++mapidx) {
                dmg->d_map[mapidx] = mark_block_free(dmg);
                dmg->r_map[mapidx] = mark_block_free(dmg);
        }

        dmg->tail = dmg->head = 0;
        // Write at 120MB/s for some time and spill into next disk
        // breaks the VM loop devices since they are fairly small

        /*
#define CLOSE_TO_MAX_SIZE_OFFSET (120 * 120 * (1024 * 1024 / GECKO_BLOCK_SIZE))
        if (dmg->size < CLOSE_TO_MAX_SIZE_OFFSET) {
                printk(DM_GECKO_PREFIX "WARNING, discarding overflow math\n");
        } else {
                dmg->tail = dmg->head = dmg->size - CLOSE_TO_MAX_SIZE_OFFSET;
        }
        */
        /*
	create_artificial_metadata_maps(dmg, dmg->size/2 + (10 * 1024),
	                                //dmg->size/16, 1);
                                        256, 256);
	*/
dm_maps_ready:

        /* alloc the htable of IO requests in-progress */
        dmg->buckets =
            kmalloc(sizeof(struct list_head) * HASH_TABLE_SIZE, GFP_KERNEL);
        if (!dmg->buckets) {
                ti->error = DM_GECKO_PREFIX "kmalloc htable failed";
                printk("%s\n", ti->error);
                err = -ENOMEM;
                goto out8;
        }

        for (i = 0; i < HASH_TABLE_SIZE; i++)
                INIT_LIST_HEAD(&dmg->buckets[i]);
        dmg->htable_size = 0;        /* rendered redundant by memset */
        dmg->head_seg = seg_for_sector(dmg, block_to_sector(dmg->head));
        ++dmg->head_seg->access_seq_in_log;
        dmg->tail_seg = seg_for_sector(dmg, block_to_sector(dmg->tail));

        ti->split_io = GECKO_SECTORS_PER_BLOCK;  /* size in # of sectors */
        ti->num_flush_requests = dmg->disk_map.stripes;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
        ti->num_discard_requests = dmg->disk_map.stripes;
#endif
        ti->private = dmg;
        sched_delayed_power_adjustment_for_segments(dmg);

        // start timer right before returning
        dmg->timer_delay = ktime_set(GECKO_TIMER_PERIOD_SECS,
                                     GECKO_TIMER_PERIOD_NSECS);
        if ((err = hrtimer_start(&dmg->timer,
                                 dmg->timer_delay,
                                 HRTIMER_MODE_REL)) != 0) {
          ti->error = DM_GECKO_PREFIX "hrtimer_start failed";
          printk("%s\n", ti->error);
          goto out8;
        }

        printk(DM_GECKO_PREFIX "gecko_ctr done (dm_gecko incarnation %llu).\n",
               dmg->incarnation);
        return 0;
out8:
        vfree(dmg->r_map);
out7:
        vfree(dmg->d_map);
out6:
        dm_gecko_put_devices(ti, dmg);
out5:
        dm_io_client_destroy(dmg->io_client);
out4:
        dmg_kcopyd_client_destroy(dmg->kcopyd_client);
out3:
        free_percpu(dmg->stats);
out2:
        kfree(dmg);
out1:
        return err;
}

static long (*sys_rename_wrapper)(const char __user *oldname,
                                  const char __user *newname) = NULL;

/* store gecko metadata persistently */
static int store_dm_gecko(struct dm_gecko *dmg)
{
        struct dm_gecko_persistent_metadata* dmg_meta;
        struct dm_gecko_dev *dmg_devs;
        struct dm_dev_seg *seg;
        size_t i, map_size;
        int sz, err = 0;
        u32 rand_bytes;
        struct file *file;
        loff_t pos = 0;
        char *meta_filename_tmp, *page;
        char *dmg_devs_offset;
        mm_segment_t old_fs = get_fs();

        page = (char *)__get_free_page(GFP_KERNEL);
        if (!page)
                return -ENOMEM;

        if (sys_rename_wrapper != NULL) {
                // the temp filename consists of the original filename
                // concatenated with the hex value of sizeof(rand_bytes)
                // random bytes (a nibble is represented by one character).
                meta_filename_tmp = kmalloc(strlen(dmg->meta_filename) + 1 +
                        sizeof(rand_bytes) * 2, GFP_KERNEL);
                if (!meta_filename_tmp) {
                        err = -ENOMEM;
                        goto out_free_page;
                }
                get_random_bytes(&rand_bytes, sizeof(rand_bytes));
                sprintf(meta_filename_tmp, "%s%x",
                        dmg->meta_filename, rand_bytes);
        } else {
                meta_filename_tmp = dmg->meta_filename;
        }
        set_fs(KERNEL_DS);

        file = filp_open(meta_filename_tmp,
                         O_LARGEFILE | O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (!file) {
                printk(DM_GECKO_PREFIX "open %s\n", dmg->meta_filename);
                err = -EIO;
                goto out;
        }

        dmg_meta = (struct dm_gecko_persistent_metadata *)page;

        dmg_meta->incarnation = dmg->incarnation;
        dmg_meta->magic = DM_GECKO_META_MAGIC;
        dmg_meta->size = dmg->size;
        dmg_meta->tail = dmg->tail;
        dmg_meta->head = dmg->head;
        dmg_meta->available_blocks = dmg->available_blocks;
        dmg_meta->free_blocks = dmg->free_blocks;
        dmg_meta->layout = dmg->disk_map.layout;
        dmg_meta->stripes = dmg->disk_map.stripes;
        dmg_meta->disk_map_cnt = dmg->disk_map.cnt;
        dmg_meta->flags = dmg->flags;
	dmg_meta->max_gc_req_in_progress = dmg->max_gc_req_in_progress;
        // Clear the volatile flags.
        clear_bit(DM_GECKO_GC_FORCE_STOP, &dmg_meta->flags);
        clear_bit(DM_GECKO_FINAL_SYNC_METADATA, &dmg_meta->flags);
        clear_bit(DM_GECKO_SYNCING_METADATA, &dmg_meta->flags);
        dmg_meta->gc_ctrl = dmg->gc_ctrl;
        dmg_meta->low_pow_state = dmg->low_pow_state;

        dmg_devs_offset = page + sizeof(*dmg_meta);
        dmg_devs = (struct dm_gecko_dev *)dmg_devs_offset;
        if (dmg_meta->disk_map_cnt * dmg_meta->stripes * sizeof(*dmg_devs) >
            PAGE_SIZE - sizeof(*dmg_meta)) {
                printk(DM_GECKO_PREFIX "metadata too large (too many disks)\n");
                err = -EINVAL;
                goto out_close;
        }

        /* populate the disk map w/ disk device names */
        list_for_each_entry(seg, &dmg->disk_map.dm_dev_segs, list) {
                int i;
                for (i = 0; i < dmg->disk_map.stripes; i++) {
                        dev_t _dev;

                        BUG_ON(seg->dev[i] == NULL);

                        _dev = seg->dev[i]->bdev->bd_dev;
                        sprintf(dmg_devs->name, "%u:%u", MAJOR(_dev),
                                MINOR(_dev));
                        ++dmg_devs;
                }
        }

        BUG_ON(((unsigned long)dmg_devs) - ((unsigned long)dmg_meta)
               > PAGE_SIZE);
        /* Write PAGE_SIZE worth of data, to align subsequent maps */
        sz = vfs_write(file, page, PAGE_SIZE, &pos);
        if (sz != PAGE_SIZE) {
                err = (sz < 0) ? sz : -EIO;
                printk(DM_GECKO_PREFIX "vfs_write metadata, dev-map %d\n", err);
                goto out_close;
        }

        /* Write the maps, both maps have the same size, further, the
         * allocated (but possibly unused) size of the maps is a
         * multiple of PAGE_SIZE to make potentially selective
         * metadata writing easier (and more efficient). */
        map_size = PAGE_ALIGN(sizeof(*dmg->d_map) * dmg->size);
        for (i = 0; i < map_size; i += PAGE_SIZE) {
                char *src = &((char *)dmg->d_map)[i];

                sz = vfs_write(file, src, PAGE_SIZE, &pos);
                if (sz != PAGE_SIZE) {
                        err = (sz < 0) ? sz : -EIO;
                        printk(DM_GECKO_PREFIX "vfs_write ->d_map\n");
                        goto out_close;
                }
        }
        for (i = 0; i < map_size; i += PAGE_SIZE) {
                char *src = &((char *)dmg->r_map)[i];

                sz = vfs_write(file, src, PAGE_SIZE, &pos);
                if (sz != PAGE_SIZE) {
                        err = (sz < 0) ? sz : -EIO;
                        printk(DM_GECKO_PREFIX "vfs_write ->r_map\n");
                        goto out_close;
                }
        }

out_close:
        filp_close(file, current->files);

        if (sys_rename_wrapper != NULL) {
                err = sys_rename_wrapper(meta_filename_tmp, dmg->meta_filename);
                if (err) {
                        printk(DM_GECKO_PREFIX "sys_rename: %d\n", err);
                        goto out;
                }
        }

out:
        if (sys_rename_wrapper != NULL) {
                kfree(meta_filename_tmp);
        }
out_free_page:
        free_page((unsigned long)page);
        set_fs(old_fs);
        return err;
}

static void gecko_dtr(struct dm_target *ti)
{
        // At this point, `dmsetup message' cannot be issued against
        // the module any longer, therefore only the extant
        // metadata-sync and gc may be running (besides regular IOs
        // that have not yet completed).
        struct dm_gecko *dmg = (struct dm_gecko *)ti->private;

        // Wait for pending metadata sync to complete.
        down_write(&dmg->metadata_sync_sema);
        // Never clear this bit, the module is about to be unloaded.
        set_bit(DM_GECKO_FINAL_SYNC_METADATA, &dmg->flags);
        up_write(&dmg->metadata_sync_sema);

        set_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags);
        // Metadata sync may have restarted the timer upon exit.
        printk(DM_GECKO_PREFIX "hrtimer destroyed\n");
        atomic_set(&dmg->timer_active, 0);
        hrtimer_cancel(&dmg->timer);
        // Wait for pending IOs to complete.
        wait_event(dmg->jobs_pending_waitqueue, !atomic_read(&dmg->total_jobs));
        dmg_kcopyd_client_destroy(dmg->kcopyd_client);
        dm_io_client_destroy(dmg->io_client);
        store_dm_gecko(dmg);
        // WARNING, must be done before put_devices.
        power_up_all_segments(dmg);
        dm_gecko_put_devices(ti, dmg);
        vfree(dmg->d_map);
        vfree(dmg->r_map);
        kfree(dmg->buckets);
        free_percpu(dmg->stats);
        kfree(dmg->meta_filename);
        kfree(dmg);
        printk(DM_GECKO_PREFIX "gecko_dtr done.\n");
}

static int gecko_status(struct dm_target *ti, status_type_t type,
                        char *result, unsigned int maxlen)
{
        struct dm_gecko *dmg = (struct dm_gecko *)ti->private;
        int cpu, sz = 0;        /* sz is used by DMEMIT */
        struct dm_gecko_stats aggregate_stats, *cursor;
        struct deferred_stats aggregate_def_stats, *def_stats;

        memset(&aggregate_stats, 0, sizeof(aggregate_stats));
        memset(&aggregate_def_stats, 0, sizeof(aggregate_def_stats));

        for_each_possible_cpu(cpu) {
                cursor = per_cpu_ptr(dmg->stats, cpu);

                aggregate_stats.reads += cursor->reads;
                aggregate_stats.writes += cursor->writes;
                aggregate_stats.subblock_reads += cursor->subblock_reads;
                aggregate_stats.subblock_writes += cursor->subblock_writes;
                aggregate_stats.gc += cursor->gc;
                aggregate_stats.discards += cursor->discards;
                aggregate_stats.dropped_discards += cursor->dropped_discards;
                aggregate_stats.empty_barriers += cursor->empty_barriers;
                aggregate_stats.gc_recycle += cursor->gc_recycle;
                aggregate_stats.rw_clash += cursor->rw_clash;
                aggregate_stats.rw_gc_clash += cursor->rw_gc_clash;
                aggregate_stats.gc_clash += cursor->gc_clash;
                aggregate_stats.gc_rw_clash += cursor->gc_rw_clash;
                aggregate_stats.ww_clash += cursor->ww_clash;
                aggregate_stats.read_empty += cursor->read_empty;
                aggregate_stats.read_err += cursor->read_err;
                aggregate_stats.write_err += cursor->write_err;
                aggregate_stats.kcopyd_err += cursor->kcopyd_err;
                aggregate_stats.sb_read += cursor->sb_read;
                aggregate_stats.sb_write += cursor->sb_write;

                def_stats = &per_cpu(deferred_stats, cpu);
                aggregate_def_stats.gc += def_stats->gc;
                aggregate_def_stats.rw += def_stats->rw;
                aggregate_def_stats.total += def_stats->total;
        }

        switch (type) {
        case STATUSTYPE_INFO:
                DMEMIT("reads(%llu), writes(%llu), "
                       "subblock_reads(%llu), subblock_writes(%llu), "
                       "gc(%llu), discards(%llu), dropped_discards(%llu), "
                       "empty_barriers(%llu), "
                       "gc_recycle(%llu), rw_clash(%llu), rw_gc_clash(%llu), "
                       "gc_clash(%llu), gc_rw_clash(%llu), ww_clash(%llu), "
                       "read_empty (%llu), read_err(%llu), write_err(%llu), "
                       "kcopyd_err(%llu), sb_read(%llu), sb_write(%llu), "
                       "deferred_gc(%llu) deferred_rw(%llu), "
                       "deferred_total(%llu), total_jobs(%d)",
                       aggregate_stats.reads,
                       aggregate_stats.writes,
                       aggregate_stats.subblock_reads,
                       aggregate_stats.subblock_writes,
                       aggregate_stats.gc,
                       aggregate_stats.discards,
                       aggregate_stats.dropped_discards,
                       aggregate_stats.empty_barriers,
                       aggregate_stats.gc_recycle,
                       aggregate_stats.rw_clash,
                       aggregate_stats.rw_gc_clash,
                       aggregate_stats.gc_clash,
                       aggregate_stats.gc_rw_clash,
                       aggregate_stats.ww_clash,
                       aggregate_stats.read_empty,
                       aggregate_stats.read_err,
                       aggregate_stats.write_err,
                       aggregate_stats.kcopyd_err,
                       aggregate_stats.sb_read,
                       aggregate_stats.sb_write,
                       aggregate_def_stats.gc,
                       aggregate_def_stats.rw,
                       aggregate_def_stats.total,
                       atomic_read(&dmg->total_jobs));
                break;
        case STATUSTYPE_TABLE:
                DMEMIT("mode(%s{%d} | %s | %s | %s | %s) size(%lu), "
                       "htable_size(%lu), "
                       "tail(%lu|%d), head(%lu|%d), available_blocks(%lu), "
                       "free_blocks(%lu), used_blocks(%lu), "
                       "unavailable_blocks(%lu), "
                       "relocatable_blocks(%lu), gc_req_in_progress(%lu), "
                       "tail_wrap_around(%lu), head_wrap_around(%lu)",
                       dmg->disk_map.layout == linear ? "linear" :
		       (dmg->disk_map.layout == raid1 ? "raid1" : 
			(dmg->disk_map.layout == raid0 ? "raid0" : "unknown")),
		       dmg->disk_map.stripes,
                       test_bit(DM_GECKO_GC_FORCE_STOP,
                                &dmg->flags) ? "gc-off"
                       : (test_bit(DM_GECKO_GC_STARTED, &dmg->flags) ?
                          "gc-on" : "gc-idle"),
                       test_bit(DM_GECKO_READ_TPUT,
                                &dmg->flags) ? "max-read-tput" : "low-power",
                       test_bit(DM_GECKO_INDEPENDENT_GC,
                                &dmg->flags) ? "gc-independent" : "gc-random",
                       test_bit(DM_GECKO_SYNCING_METADATA,
                                &dmg->flags) ? "SYNC-METADATA-ON"
		       : "SYNC-METADATA-OFF",
                       (long unsigned)dmg->size,
                       (long unsigned)dmg->htable_size,
                       (long unsigned)dmg->tail, dmg->tail_seg->idx,
                       (long unsigned)dmg->head, dmg->head_seg->idx,
                       (long unsigned)dmg->available_blocks,
                       (long unsigned)dmg->free_blocks,
                       (long unsigned)__used_blocks(dmg),
                       (long unsigned)__unavailable_blocks(dmg),
                       (long unsigned)__relocatable_blocks(dmg),
                       (long unsigned)dmg->gc_req_in_progress,
                       dmg->tail_wrap_around,
                       dmg->head_wrap_around);
                if (test_bit(DM_GECKO_STATUS_DETAILED, &dmg->flags)) {
#define DMG_STATE0 0
#define DMG_STATE1 1
                        u32 tail, loopcnt, cursor, next_free, total_free;
                        u32 automata_state = DMG_STATE0;

                        DMEMIT("\n" DM_GECKO_PREFIX
                               "detail: tail=%lu, head=%lu\n",
                               (long unsigned)dmg->tail,
                               (long unsigned)dmg->head);

                        tail = dmg->tail;
                        cursor = dmg->tail;
                        next_free = dmg->tail;
                        total_free = 0;
                        for (loopcnt = 0; loopcnt < MAX_DETAIL_LOG_LOOP_CNT;) {

                                if (cursor == dmg->head)
                                        break;

                                switch (automata_state) {
                                case DMG_STATE0:
                                        if (is_block_marked_free
                                            (dmg->r_map[cursor], dmg)) {
                                                next_free = cursor;
                                                total_free = 1;
                                                automata_state = DMG_STATE1;
                                        }
                                        break;
                                case DMG_STATE1:
                                        if (!is_block_marked_free
                                            (dmg->r_map[cursor], dmg)) {
                                                DMEMIT("%lu:%lu\n",
                                                       (long unsigned)
                                                       next_free,
                                                       (long unsigned)
                                                       total_free);
                                                ++loopcnt;
                                                total_free = 0;
                                                automata_state = DMG_STATE0;
                                        }
                                        break;
                                default:
                                        BUG_ON(1);
                                }

                                if ((++cursor) == dmg->size) {
                                        /* wrap around */
                                        cursor = 0;
                                }
                        }
                }
                break;
        }

        return 0;
}

static int gecko_message(struct dm_target *ti, unsigned argc, char **argv)
{
        struct dm_gecko *dmg = (struct dm_gecko *)ti->private;

        if (argc < 1 || argc > 3) {
                ti->error = DM_GECKO_PREFIX "invalid number of arguments";
                goto bad;
        }

        if (strcmp(argv[0], "set-low-power") == 0) {
                if (argc == 2) {
                        if (strcmp(argv[1], "sleep") == 0) {
                                dmg->low_pow_state = sleep;
                        } else if (strcmp(argv[1], "standby") == 0) {
                                dmg->low_pow_state = standby;
                        } else {
                                printk(DM_GECKO_PREFIX
                                       "invalid set-low-power parameter: %s\n",
                                       argv[1]);
                                goto bad;
                        }
                }
                clear_bit(DM_GECKO_READ_TPUT, &dmg->flags);
                sched_delayed_power_adjustment_for_segments(dmg);
        } else if (strcmp(argv[0], "set-high-read-tput") == 0) {
                set_bit(DM_GECKO_READ_TPUT, &dmg->flags);
                /* Need not need to power-up the mirrored disks
                 * explicitly, the Linux IDE driver is supposed to
                 * issue the reset lazyly and on demand. Do it anyway. */
                 power_up_all_segments(dmg);
        } else if (strcmp(argv[0], "gc-independent") == 0) {
                set_bit(DM_GECKO_INDEPENDENT_GC, &dmg->flags);
                power_up_segment(seg_for_sector(dmg,
                                                block_to_sector(dmg->tail)));
        } else if (strcmp(argv[0], "gc-off") == 0) {
                set_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags);
                clear_bit(DM_GECKO_GC_STARTED, &dmg->flags);
        } else if (strcmp(argv[0], "gc-on") == 0) {
                clear_bit(DM_GECKO_GC_FORCE_STOP, &dmg->flags);
                set_bit(DM_GECKO_GC_STARTED, &dmg->flags);
        } else if (strcmp(argv[0], "detail-on") == 0) {
                set_bit(DM_GECKO_STATUS_DETAILED, &dmg->flags);
        } else if (strcmp(argv[0], "detail-off") == 0) {
                clear_bit(DM_GECKO_STATUS_DETAILED, &dmg->flags);
        } else if (strcmp(argv[0], "sync-metadata") == 0) {
                do_sync_metadata(dmg);
        } else if (strcmp(argv[0], "sync-metadata-asynchronously") == 0) {
                queue_work(gecko_sync_metadata_wqueue,
                           &dmg->sync_metadata_work);
	} else if (strcmp(argv[0], "set-gc-max-concurrent-requests") == 0) {
	        int max_gc_concurrent_req;
		if (argc < 2) {
		        ti->error =
			  DM_GECKO_PREFIX "too few args (need one integer)";
			goto bad;
		}
		max_gc_concurrent_req = simple_strtol(argv[1], NULL, 10);
		if (max_gc_concurrent_req < MIN_GC_CONCURRENT_REQ ||
		    max_gc_concurrent_req > MAX_GC_CONCURRENT_REQ) {
		        ti->error =
			  DM_GECKO_PREFIX "invalid argument (not in range)";
			goto bad;
		}
		dmg->max_gc_req_in_progress = max_gc_concurrent_req;
        } else if (strcmp(argv[0], "set-gc-watermarks") == 0) {
                unsigned long low_gc_watermark, high_gc_watermark;
                if (argc < 3) {
                        ti->error =
			  DM_GECKO_PREFIX "too few args (need 2 watermarks)";
                        goto bad;
                }
                low_gc_watermark = simple_strtoul(argv[1], NULL, 10);
                high_gc_watermark = simple_strtoul(argv[2], NULL, 10);
                if (low_gc_watermark >= high_gc_watermark) {
                        ti->error =
                            DM_GECKO_PREFIX "low watermark >= high watermark";
                        goto bad;
                }
                dmg->gc_ctrl.low_watermark = low_gc_watermark;
                dmg->gc_ctrl.high_watermark = high_gc_watermark;
        } else {
                ti->error = DM_GECKO_PREFIX "invalid dmsetup message";
                goto bad;
        }

        return 0;
bad:
        printk("%s\n", ti->error);
        return -EINVAL;
}

static struct target_type gecko_target = {
        .name = "gecko",
        .version = {1, 0, 1},
        .module = THIS_MODULE,
        .ctr = gecko_ctr,
        .dtr = gecko_dtr,
        .map = gecko_map,
        .status = gecko_status,
        .message = gecko_message,
};

static int __init dm_gecko_init(void)
{
        int err = -ENOMEM;

#ifdef CONFIG_KALLSYMS
        unsigned long sys_rename_addr = kallsyms_lookup_name("sys_rename");
        if (sys_rename_addr == 0) {
                printk(DM_GECKO_PREFIX "Unable to lookup sys_rename symbol\n");
        } else {
                sys_rename_wrapper = (void *) sys_rename_addr;
                printk(DM_GECKO_PREFIX "Found sys_rename at address 0x%p\n",
                       sys_rename_wrapper);
        }
#elif defined SYS_RENAME_EXPORTED_TO_MODULES
        sys_rename_wrapper = sys_rename;
#endif

        /* init global resources for all gecko targets at module load
         * time */
        if ((err = dmg_kcopyd_init()) != 0) {
                printk(DM_GECKO_PREFIX "Unable to init kcopyd\n");
                goto out1;
        }
        if (!(io_for_block_cache = KMEM_CACHE(io_for_block, 0))) {
                printk(DM_GECKO_PREFIX "Unable to alloc io_for_block cache\n");
                goto out1;
        }

        if (!(io_job_cache = KMEM_CACHE(io_job, 0))) {
                printk(DM_GECKO_PREFIX "unable to alloc io_job cache\n");
                goto out2;
        }

        io_for_block_mempool = mempool_create_slab_pool(MIN_JOBS_IN_POOL,
                                                        io_for_block_cache);
        if (!io_for_block_mempool) {
                printk(DM_GECKO_PREFIX
		       "unable to alloc io_for_block mempool\n");
                goto out3;
        }

        io_job_mempool = mempool_create_slab_pool(MIN_JOBS_IN_POOL,
                                                  io_job_cache);
        if (!io_job_mempool) {
                printk(DM_GECKO_PREFIX "unable to alloc io_job mempool\n");
                goto out4;
        }

        /* The correctness of the algorithms rely on the assumption
         * that gecko_wqueue is a singlethreaded workqueue. */
        if (!(gecko_wqueue = create_singlethread_workqueue("geckod"))) {
                printk(DM_GECKO_PREFIX "unable to create geckod workqueue\n");
                goto out5;
        }
        INIT_WORK(&gecko_work, run_deferred_jobs);

        if (!(gecko_sync_metadata_wqueue =
              create_singlethread_workqueue("geckod-meta"))) {
                printk(DM_GECKO_PREFIX
                       "unable to create geckod-meta workqueue\n");
                goto out6;
        }

        if ((err = dm_register_target(&gecko_target)) < 0) {
                printk(DM_GECKO_PREFIX "register target failed %d\n", err);
                goto out7;
        }

        printk(DM_GECKO_PREFIX "module loaded\n");
        return 0;
out7:
        destroy_workqueue(gecko_sync_metadata_wqueue);
out6:
        destroy_workqueue(gecko_wqueue);
out5:
        mempool_destroy(io_job_mempool);
out4:
        mempool_destroy(io_for_block_mempool);
out3:
        kmem_cache_destroy(io_job_cache);
out2:
        kmem_cache_destroy(io_for_block_cache);
out1:
        return err;
}

static void __exit dm_gecko_exit(void)
{
        dm_unregister_target(&gecko_target);
        BUG_ON(!list_empty(&deferred_jobs));
        mempool_destroy(io_job_mempool);
        mempool_destroy(io_for_block_mempool);
        kmem_cache_destroy(io_job_cache);
        kmem_cache_destroy(io_for_block_cache);
        destroy_workqueue(gecko_wqueue);
        destroy_workqueue(gecko_sync_metadata_wqueue);
        dmg_kcopyd_exit();
        printk(DM_GECKO_PREFIX "module unloaded\n");
}

module_init(dm_gecko_init);
module_exit(dm_gecko_exit);

MODULE_DESCRIPTION("Gecko: power saving log structured storage system");
MODULE_AUTHOR("Tudor Marian <tudorm@cs.cornell.edu>");
#ifndef MODULE_LICENSE
#define MODULE_LICENSE(a)
#endif
MODULE_LICENSE("Dual BSD/GPL");
