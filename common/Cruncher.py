#!/usr/bin/env python3

import shlex
import readline
import os
import re
import socket
import sys
import pickle
class Cruncher:

    def __init__(self):
        self.running = True
        self.debugging = False
        self.init_commands = []
        self.settings = {
                        "validate_timeout": "2",
                        "savestate_loc": "./state.crunch",
                        "autosave": "False"
        }
        self.credentials = CredBucket()
        self.hosts = HostBucket()
        self.shares = ShareBucket()
        self.display_header()
        self.commands = {
                        "stats": ["Get stats on currently loaded data", "get_stats"],
                        "list": ["List currently loaded data of one type", "list_data"],
                        "validate": ["Attempts to validate hosts/shares/creds", "validate_data"],
                        "add": ["Add an individual host, share, or cred", "add_item"],
                        "set": ["Set an internal setting variable", "set_var"],
                        "save": ["Save current state to a file (default location: ./state.crunch)", "savestate"],
                        "restore": ["Restores a previously saved state", "restorestate"],
                        "!": ["Run a system command from within SMBCrunch", "system_cmd"],
                        "load": ["Load a file into hosts, shares, or creds", "load_file"],
                        "debug": ["Sets debug mode on/off", "set_debugging"],
                        "help": ["Shows the help menu", "show_help"],
                        "exit": ["Exits SMBCrunch", "crunch_exit"],
        }

        self.usage = {
                        "stats": "",
                        "list": "list (hosts|shares|creds)",
                        "validate": "validate (hosts|shares|creds) [all]",
                        "add": "add (host|share|cred) <data>",
                        "set": '''set variable value\n
            Variables include:
                validate_timeout   - Timeout of the validation of data types
                savestate_loc      - Location of the state save
                autosave           - Auto-save state after each command''',
                        "save": "save",
                        "restore": "restore [file]",
                        "!": "! <command>",
                        "load": "load (hosts|shares|creds) <file>",
                        "debug": "debug (on|off)",
                        "help": "",
                        "exit": ""
        }
        return


    def parse_cli_args(self, args):
        self.init_commands = args
        for i in range(len(args)):
            print (str(i) + ": " + str(args[i]))

    def run_cmd(self, cmd):
        print("\n")
        self.debug("Running command: \"" + cmd +"\"")

        cmd_parts = shlex.split(cmd)
        c = cmd_parts[0].lower()
        if c in self.commands.keys():
            func_to_run = getattr(self, self.commands[c][1])
            func_to_run(cmd_parts)
        else:
            print("[!] Invalid command: \"" + c + "\" - Type \"help\" for help")
    
    def savestate(self, parts):
        
        data = {
                "credentials": self.credentials,
                "shares": self.shares,
                "hosts": self.hosts,
                "settings": self.settings
        }
    
        pickle.dump(data, open(self.settings['savestate_loc'], 'wb'))
        
        print("\t[!] State saved to disk at: " + self.settings['savestate_loc'])

    def restorestate(self, parts):
        loc = self.settings['savestate_loc']
        if len(parts) > 1:
            loc = " ".join(parts[1:])
        
        if not os.path.isfile(loc):
            print("\t[!] ERROR: Unable to restore state: Could not find file")
            return

        try:
            data = pickle.load(open(loc, 'rb'))
            self.credentials = data['credentials']
            self.shares = data['shares']
            self.hosts = data['hosts']
            self.settings = data['settings']
            print("\t[~] Succesfully imported previous state!")
        except IndexError:
            print("\t[!] Invalid file")
        except KeyError:
            print("\t[!] Could not parse file")


    def add_item(self, parts):
        if len(parts) < 3:
            self.show_usage('add')
            return
        data_type = parts[1].lower()
        if data_type == "host":
            h = Host.parse(" ".join(parts[2:]))
            if h:
                if self.hosts.add(h):
                    print("\tHost added successfully")
                else:
                    print("\tHost was already present in the dataset")
            else:
                print("\tHost was unable to be parsed.  Make sure its a valid host or IP")
        elif data_type == "share":
            s = Share.parse(str(parts[2:]))
            if s:
                if self.shares.add(s):
                    print("\tShare added successfully")
                else:
                    print("\tShare was already present in the datasec")
            else:
                print("\tShare was unable to be parsed.  Make sure its in a valid \\\\Host\\Share format")
        elif data_type == "cred":
            c = Cred.parse(str(parts[2:]))
            if c:
                if self.credentials.add(c):
                    print("\tCredential added successfully")
                else:
                    print("\tCredential was already present in the dataset")
            else:
                print("\tCredential was unable to be parsed.  Make sure its in a valid DOMAIN\\Username:Password format")
        else:
            self.show_usage('add')

    def validate_data(self, parts):
        if len(parts) < 2:
            self.show_usage('validate')
            return
        all = False
        if len(parts) > 2 and parts[2].lower() == "all":
            all = True
        type = parts[1].lower()
        if type == "hosts":
            listHosts = self.hosts.get_all_unknown()
            if all:
                listHosts = self.hosts
            if len(listHosts) == 0:
                print("\t[!] No hosts remaining to validate (to revalidate all, do \"validate hosts all\")")
                return
            for h in listHosts:
                print("\t[~] Validating {:.<30}".format(h.host), end="")
                sys.stdout.flush()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(int(self.settings['validate_timeout']) or 2)
                try:
                    s.connect((h.host, 445))
                    s.close()
                    h.set_valid()
                    print("Valid")
                except:
                    h.set_invalid()
                    print("Invalid")
                sys.stdout.flush()
        
        if type == "creds":
            listCreds = self.credentials.get_all_unknown()
            if all:
                listCreds = self.credentials
            if len(listCreds) == 0:
                print("\t[!] No credentials to validate (to revalidate all, do \"validate creds all\")")
                return
            for c in listCreds:
                print("\t[~] Validating {:.<30}".format(c.username), end="")
                # do smbclient things
                print("Valid")

        if type == "shares":
            listShares = self.shares.get_all_unknown()
            if all:
                listShares = self.shares
            if len(listShares) == 0:
                print("\t[!] No shares to validate (to revalidate all, do \"validate shares all\")")
                return
            for s in listShares:
                print("\t[~] Validating {:.<30}".format(("\\\\"+s.host+"\\"+s.share)),end="")
                # do smbclient things
                print("Valid")



    def list_data(self, parts):
        if len(parts) != 2:
            self.show_usage('list')
            return
        data_type = parts[1].lower()
        if data_type == "hosts":
            print(str(self.hosts))
        elif data_type == "shares":
            print(str(self.shares))
        elif data_type == "creds":
            print(str(self.credentials))
        else:
            self.show_usage('list')
    
    def get_stats(self, parts):
        print("Current Stats:")
        print("\tCredentials loaded: " + str(len(self.credentials)))
        print("\t\t- " + str(len(self.credentials.get_all_valid())) + " valid")
        print("\t\t- " + str(len(self.credentials.get_all_invalid())) + " invalid")
        print("\t\t- " + str(len(self.credentials.get_all_unknown())) + " untested")
        self.debug(str(self.credentials))
        print("\n")
        print("\tHosts loaded: " + str(len(self.hosts)))
        print("\t\t- " + str(len(self.hosts.get_all_valid())) + " valid")
        print("\t\t- " + str(len(self.hosts.get_all_invalid())) + " invalid")
        print("\t\t- " + str(len(self.hosts.get_all_unknown())) + " unknown")
        self.debug(str(self.hosts))
        print("\n")
        print("\tShares loaded: " + str(len(self.shares)))
        print("\t\t- " + str(len(self.shares.get_all_valid())) + " valid")
        print("\t\t- " + str(len(self.shares.get_all_invalid())) + " invalid")
        print("\t\t- " + str(len(self.shares.get_all_unknown())) + " unknown")
        self.debug(str(self.shares))

    def system_cmd(self, parts):
        if len(parts) > 1:
            cmd = " ".join(parts[1:])
            self.debug("Running system command \"" + cmd + "\"")
            os.system(cmd)
        else:
            self.show_usage('!')

    def load_file(self, parts):
        if len(parts) > 2 and parts[1] in ["shares", "creds", "hosts"]:
            num_loaded = 0
            num_already_seen = 0
            type = "credentials"
            if parts[1] == "shares":
                type = "shares"
            elif parts[1] == "hosts":
                type = "hosts"
            filename = " ".join(parts[2:])
            if os.path.isfile(filename):
                with open(filename) as file:
                    for line in file:
                        if not line.strip():
                            continue
                        if parts[1] == "creds":
                            self.debug("Attempting to add credential: " + line.strip())
                            c = Cred.parse(line.rstrip('\n'))
                            if c:
                                if self.credentials.add(c):
                                    num_loaded += 1
                                else:
                                    num_already_seen += 1
                            else:
                                self.debug("Unknown credential: " + line.rstrip('\n'))
                        elif parts[1] == "shares":
                            self.debug("Attempting to add share: " + line.strip())
                            s = Share.parse(line.rstrip('\n'))
                            if s:
                                if self.shares.add(s):
                                    num_loaded += 1
                                else:
                                    num_already_seen += 1
                            else:
                                self.debug("Unknown share: " + line.rstrip('\n'))
                        elif parts[1] == "hosts":
                            self.debug("Attempting to add host: " + line.strip())
                            h = Host.parse(line.rstrip('\n'))
                            if h:
                                if self.hosts.add(h):
                                    num_loaded += 1
                                else:
                                    num_already_seen += 1
                            else:
                                self.debug("Unknown host: " + line.rstrip('\n'))
                print("[~] " + str(num_loaded) + " " + type + " have been added",end="")
                if num_already_seen > 0:
                    print(" (" + str(num_already_seen) + " already existed)")
                else:
                    print("")
        else:
            self.show_usage("load")
    
    def set_debugging(self,parts):
        if len(parts) == 2:
            if parts[1].lower() == "on":
                self.debugging = True
                print("[~] Setting debug to ON")
            elif parts[1].lower() == "off":
                self.debugging = False
                print("[~] Setting debug to OFF")
            else:
                print("[!] Invalid argument for \"debug\": \"" + parts[1] + "\"")
        else:
            self.show_usage('debug')

    def show_help(self,parts):
        if len(parts) > 1:
            if parts[1] in self.commands.keys() and self.usage[parts[1]] != "":
                print("Help for \"" + parts[1] + "\":\n")
                print("\tInfo: " + self.commands[parts[1]][0] + "\n")
                print("\tUsage: " + self.usage[parts[1]] + "\n")
            else:
                print("Command \"" + parts[1] + "\" not found!")
        else:
            print("Help menu:")
            for cmd in sorted(self.commands.keys()):
                print(("\t{:<30} -\t" + self.commands[cmd][0]).format(cmd))

    def crunch_exit(self, parts):
        self.running = False

    def main_menu(self):
        readline.parse_and_bind("tab: complete")
        if len(self.init_commands) > 0:
            print("[~] Executing commands given on command line")
            for cmd in self.init_commands:
                self.run_cmd(cmd)
            print("[~] Done executing the init commands")
        while self.running:
            input_cmd = input("\n\n[>] Command: ").strip()
            if input_cmd:
                self.run_cmd(input_cmd)
    
    def display_header(self):
        print('''

        SMBCruncher!

        By Chris King

        ''')


    def show_usage(self, cmd):
        print("[!] Usage: \"" + self.usage[cmd] + "\"")

    def debug(self, stri):
        if self.debugging:
            print("[!DEBUG!] " + str(stri))




class CrunchableBucket(object):
    def __init__(self):
        self.title = "CrunchableBucket"
        self.container = []

    def add(self, crunchable):
        exists = False
        for c in self.container:
            if c == crunchable:
                exists = True
                break
        if not exists:
            self.container.append(crunchable)
            return True
        else:
            return False

    def get_all(self):
        return self.container

    def get_all_valid(self):
        valid = []
        for c in self.container:
            if c.is_valid():
                valid.append(c)
        return valid

    def get_all_invalid(self):
        invalid = []
        for c in self.container:
            if c.is_invalid():
                invalid.append(c)
        return invalid

    def get_all_unknown(self):
        unknown = []
        for c in self.container:
            if c.is_unknown():
                unknown.append(c)
        return unknown

    def __len__(self):
        return len(self.container)

    def __getitem__(self, i):
        return self.container[i]

    def __setitem__(self, i, val):
        self.container[i] = val

    def __str__(self):
        output_str = self.title + ":\n"
        for c in self.container:
            output_str += "\t"+str(c)+"\n"
        return output_str

class Crunchable(object):
    def __init__(self, valid=2):
        self.valid = valid

    def set_valid(self):
        self.valid = 1

    def set_invalid(self):
        self.valid = 0

    def set_unknown(self):
        self.valid = 2

    def is_valid(self):
        return (self.valid == 1)

    def is_invalid(self):
        return (self.valid == 0)

    def is_unknown(self):
        return (self.valid == 2)

    def __str__(self):
        type = "Unknown"
        if self.valid == 1:
            type = "Valid"
        elif self.valid == 0:
            type = "Invalid"
        return '{:<30}  - {:<7}'.format(self.to_str(),type)

    def __eq__(self, other):
        return self.eq(other)

    ## Override these functions:
    def to_str(self):
        return "Stock Crunchable"

    def parse(parsable):
        return False
    
    def eq(self):
        return false


class ShareBucket(CrunchableBucket):
    def __init__(self):
        super().__init__()
        self.title = "List of Shares"

class Share(Crunchable):
    
        def __init__(self, sharename, host,valid=2):
            self.share = sharename
            self.host = host
            super().__init__(valid)

        def parse(parsable):
            # \\Host\\Share
            m = re.match(r"^\\\\(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\\([^\\]+)\\?.*$", parsable)
            if m is not None:
                return Share(m.group(4), m.group(3))
            return False

        def to_str(self):
            return "\\\\" + self.host + "\\" + self.share

        def eq(self, other):
            return (self.host == other.host and self.share == other.share)



class HostBucket(CrunchableBucket):

    def __init__(self):
        super().__init__()
        self.title = "List of Hosts"



class Host(Crunchable):

    def __init__(self, hostname, valid=2):
        self.host = hostname
        super().__init__(valid)

    
    def parse(parsable):
        if re.match("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", parsable) is not None:
            return Host(parsable)
        return False

    def to_str(self):
        return self.host

    def eq(self, other):
        return (self.host == other.host)


class CredBucket(CrunchableBucket):

    def __init__(self):
        super().__init__()
        self.title = "List of Credentials"


class Cred(Crunchable):

    def __init__(self, domain, username, password, valid=2):
        self.domain = domain
        self.username = username
        self.password = password
        super().__init__(valid)

    def parse(parsable, user_pass_sep=':', domain_user_sep='\\'):
        if user_pass_sep not in parsable:
            return False
        domain = ""
        username = ""
        password = ""
        domain_user,password = parsable.split(':',1)
        if domain_user_sep not in domain_user:
            domain = 'localhost'
            username = domain_user
        else:
            domain,username = domain_user.split('\\',1)
        return Cred(domain, username, password)

    def to_str(self):
        return self.domain + "\\" + self.username + ":" + self.password

    def eq(self, other):
        return (self.domain == other.domain and self.username == other.username and self.password == other.password)

