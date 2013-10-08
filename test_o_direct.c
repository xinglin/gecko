
/*
 * Copyright (C) 2011 Tudor Marian <tudorm@cs.cornell.edu>
 */

/* The write-write conflicts appear way more often if I run this in a
 * VM w/ 2 cores */
#define _GNU_SOURCE /* for O_DIRECT, must be before the #include
                     * statements */
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#define PRINT_CONFLICT_EVERY_N  400
#define MAX_THREAD_CNT          64
#define BUFSZ                   512

static int BLK_RANGE = 0;

struct runner_info {
	int       idx;
        int       cnt;
	pthread_t id;
	void      *arg;
};

void *pthread_run(void *arg)
{
	char *page, *second_page;
	int i, fd, PAGESIZE = getpagesize(), sz, conflicts = 0;
	struct runner_info *ti = arg;

	page = mmap(NULL, 2 * PAGESIZE, PROT_READ | PROT_WRITE,
                    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	assert (page != MAP_FAILED);
	sprintf(page, "thread %d page write", ti->idx);
	sz = strlen(page);
	page[sz++] = '\0'; /* terminate string so we can strcmp */
	/* I can force sub-page IO by just aligning to 512 blocks! */
        assert (((unsigned long) page & (unsigned long) (PAGESIZE-1)) == 0);
	second_page = page + PAGESIZE;
	fd = open((char *) ti->arg, O_DIRECT | O_RDWR);
        assert (fd >= 0);

	fprintf(stdout, "started thread #%u\n", ti->idx);
	sleep(1);
        assert(BLK_RANGE > 0);
	for (i = 0; i < ti->cnt; i++) {
		ssize_t byte_cnt;
		int block = rand() % BLK_RANGE;

		lseek(fd, block * PAGESIZE, SEEK_SET);
		byte_cnt = write(fd, page, PAGESIZE);
                assert (byte_cnt == PAGESIZE);
                //continue;
                /* These seeks back to check for data are mighty
                 * expensive */
		lseek(fd, block * PAGESIZE, SEEK_SET);
		byte_cnt = read(fd, second_page, PAGESIZE);
                assert (byte_cnt >= 0);
		if (byte_cnt == 0) {
			fprintf(stdout, "End of file\n");
			break;
		}
		if (strcmp(page, second_page) != 0) {
                        ++conflicts;
                        if ((conflicts % PRINT_CONFLICT_EVERY_N) == 0) {
                                printf("write-write conflict (%d); "
                                       "thread %d, block %d: <%s> : <%s>\n",
                                       conflicts, ti->idx, block,
                                       page, second_page);
                        }
                }
	}
        fprintf(stdout, "Thread #%u encountered %d write-write conflicts\n",
                ti->idx, conflicts);
	return NULL;
}

int main(int argc, char *argv[])
{
        int i, cnt, thread_cnt;
	struct runner_info runners[MAX_THREAD_CNT];

	if (argc != 5) {
		fprintf(stderr, "Usage %s <dm-dev-file> <block_range> "
                        "<loop-cnt> <threads>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
        BLK_RANGE = atoi(argv[2]);
        if (BLK_RANGE < 0) {
          fprintf(stderr, "Invalid block range, must be positive integer\n");
          exit(EXIT_FAILURE);
        }
        cnt = atoi(argv[3]);
        if (cnt < 0) {
          fprintf(stderr, "Invalid loop cnt, must be a non-negative "
                  "integer\n");
          exit(EXIT_FAILURE);
        }
        thread_cnt = atoi(argv[4]);
        if (thread_cnt <= 0 || thread_cnt > MAX_THREAD_CNT) {
          fprintf(stderr, "Invalid # of thread=%d, must be in [1, %d]\n",
                  thread_cnt, MAX_THREAD_CNT);
          exit(EXIT_FAILURE);
        }

	for (i = 0; i < thread_cnt; i++) {
		runners[i].idx = i;
                runners[i].cnt = cnt;
		runners[i].arg = argv[1];
		assert(pthread_create(&runners[i].id,
                                      NULL,
                                      pthread_run,
                                      &runners[i]) == 0);
	}
	for (i = 0; i < thread_cnt; i++) {
                assert(pthread_join(runners[i].id, NULL) == 0);
	}
	exit(EXIT_SUCCESS);
}
