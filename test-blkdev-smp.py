
# Copyright (C) 2011 Tudor Marian <tudorm@cs.cornell.edu>

import sys,os,resource,hashlib,random
from threading import Thread
from multiprocessing import Process

# fire up a bunch of threads and concurrently write to the same block

PAGESIZE = resource.getpagesize()
msg = 'ana are mere, dora minodora are pere'	

blocks = range(2)
cnt = 10000
runners_cnt = 6

def run_fn(filename, cnt, idx):
	# O_DIRECT not supported in python since can't align user buffer to 
	# page (or sector for Linux kernels >= 2.6) boundary. Can use O_SYNC 
	# for synchronous writes which the kernel will flush to disk (controller)
	flags = os.O_RDWR | os.O_SYNC
	flags = os.O_RDWR
	fd = os.open(filename, flags)
	dev_sz = os.lseek(fd, 0, os.SEEK_END)
	os.lseek(fd, 0, os.SEEK_SET)
	
	i = 0
	try:
		while i < cnt:
			block = random.choice(blocks)
			os.lseek(fd, block*PAGESIZE, os.SEEK_SET)
			sz = os.write(fd, msg)
			os.lseek(fd, block*PAGESIZE, os.SEEK_SET)
			read_msg = os.read(fd, len(msg))
			assert read_msg == msg
			if (i+idx) % 10 == 0:
				os.fsync(fd)
			i += 1
	except KeyboardInterrupt, e:
		pass
	finally:
		os.close(fd)
#end run_fn

class Runner(Thread):
	def __init__(self, file, cnt):
		Thread.__init__(self)
		self.cnt = cnt
		self.file = file
	def run(self):
		run_fn(self.file, self.cnt)
#end Runner

def do_main():
	if len(sys.argv) != 2:
		sys.stderr.write('Usage: %s <dm-dev-file>\n')
		sys.exit(1)
	
	runners = []
	for i in range(runners_cnt):
		#runner = Runner(sys.argv[1], cnt)
		runner = Process(target=run_fn, args=(sys.argv[1], cnt, i))
		runners.append(runner)
	for runner in runners:
		runner.start()
	try:
		for runner in runners:
			runner.join()
	except KeyboardInterrupt, e:
		sys.exit(1)
#end do_main

if __name__ == '__main__':
	do_main()
