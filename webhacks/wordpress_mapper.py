import contextlib
import os
import queue
import requests
import time

FILTERED = [".jpg", ".jpeg", ".png", ".gif", ".css"]
TARGET = "sample-wordpress-website"
THREADS = 10
WORDPRESS = "/home/shashank/Downloads/wordpress"
answer = queue.Queue()
web_paths = queue.Queue()


def gather_paths():
    for root, _, files in os.walk('.'):
        for fname in files:
            if os.path.splitext(fname) in FILTERED:
                continue
            path = os.path.join(root, fname)
            if path.startswith('.'):
                path = path[1:]
                print(path)
                web_paths.put(path)


def test_remote(target):
    while not web_paths.empty():
        path = web_paths.get()
        url = f'{target}{path}'
        time.sleep(2)
        r = requests.get(url)
        if r.status_code == 200:
            answer.put(url)
            print(url)
        else:
            print('x')


@contextlib.contextmanager
def chdir(path):
    this_dir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(this_dir)


if __name__ == "__main__":
    with chdir(WORDPRESS):
        gather_paths()
    input('press return to continue')
    test_remote('https://rollingstones.com/')
