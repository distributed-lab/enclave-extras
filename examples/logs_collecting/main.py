#!/usr/bin/env python3
"""
Simple script: every 5 seconds print "Hello world {i}" where i is the message number.
Graceful shutdown on Ctrl+C.
"""
import time
import signal
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")

stop = False

def _handle_sigint(signum, frame):
	global stop
	stop = True

signal.signal(signal.SIGINT, _handle_sigint)

def main():
	i = 1
	while not stop:
		logging.info(f"Hello world {i}")
		i += 1
		# Sleep in 1-second chunks so Ctrl+C is responsive during sleep
		for _ in range(5):
			if stop:
				break
			time.sleep(1)
	logging.info("Shutting down")

if __name__ == "__main__":
	main()
