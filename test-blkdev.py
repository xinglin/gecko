
# Copyright (C) 2011 Tudor Marian <tudorm@cs.cornell.edu>

import sys,os,resource,hashlib,time

# fire up a bunch of threads and concurrently write to the same block

PAGESIZE = resource.getpagesize()
sleep_secs = 1

def do_main():
	if len(sys.argv) != 2:
		sys.stderr.write('Usage: %s <dm-dev-file>\n')
		sys.exit(1)
	
	# open w/ O_DIRECT so as to bypass the buffer cache or just O_FSYNC/O_SYNC
	# for synchronous writes which the kernel will flush to disk (controller)
	flags = os.O_RDWR | os.O_SYNC
	fd = os.open(sys.argv[1], flags)
	dev_sz = os.lseek(fd, 0, os.SEEK_END)
	os.lseek(fd, 0, os.SEEK_SET)
	
	msg = 'ana are mere, dora minodora are %d pere'	
	for i in range(5):
		ith_page = i*PAGESIZE
		os.lseek(fd, ith_page, os.SEEK_SET)
		page_msg = msg % (i,)
		sz = os.write(fd, page_msg)
		assert sz == len(page_msg)
		os.lseek(fd, ith_page, os.SEEK_SET)
		msg2 = os.read(fd, len(page_msg))
		assert msg2 == page_msg
		time.sleep(sleep_secs)
	
	# overwrite blocks 2, 3, and 4
	for i in range(2,5):
		ith_page = i*PAGESIZE
		os.lseek(fd, ith_page, os.SEEK_SET)
		page_msg = msg % (i,)
		sz = os.write(fd, page_msg)
		assert sz == len(page_msg)
	print 'press any key to continue...'
	line = sys.stdin.readline() # wait until things have aquiesced
	
	for i in range(5):
		ith_page = i*PAGESIZE
		os.lseek(fd, ith_page, os.SEEK_SET)
		page_msg = msg % (i,)
		msg2 = os.read(fd, len(page_msg))
		assert msg2 == page_msg
	
	sys.exit(1)
	
	line = sys.stdin.readline() # pause to check the dmsetup status/table
	# TODO: actually should NOT seek, that way will figure out if the write
	# allocated a fresh block and released the old one accordingly
	#os.lseek(fd, PAGESIZE, os.SEEK_SET)
	sz = os.write(fd, msg)
	os.lseek(fd, 0, os.SEEK_SET)
	msg2 = os.read(fd, len(msg))
	assert msg2 == msg

	os.close(fd)
#end do_main

if __name__ == '__main__':
	do_main()
