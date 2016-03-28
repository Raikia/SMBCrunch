#!/usr/bin/env python3

import shlex
import readline
import os

class Cruncher:

    def __init__(self):
        self.running = True
        self.debugging = False
        self.init_commands = []
        self.credentials = CredBucket()
        self.display_header()
        self.commands = {
                        "stats": ["Get stats on currently loaded data", "get_stats"],
                        "!": ["Run a system command from within SMBCrunch", "system_cmd"],
                        "load": ["Load a file into creds or shares", "load_file"],
                        "debug": ["Sets debug mode on/off", "set_debugging"],
                        "help": ["Shows the help menu", "show_help"],
                        "exit": ["Exits SMBCrunch", "crunch_exit"],
        }

        self.usage = {
                        "stats": "",
                        "!": "! <command>",
                        "load": "load [shares|creds] <file>",
                        "debug": "debug [on|off]",
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

    def get_stats(self, parts):
        print("Current Stats:")
        print("\tCredentials loaded: " + str(len(self.credentials)))

    def system_cmd(self, parts):
        if len(parts) > 1:
            cmd = " ".join(parts[1:])
            self.debug("Running system command \"" + cmd + "\"")
            os.system(cmd)
        else:
            self.show_usage('!')

    def load_file(self, parts):
        if len(parts) > 2 and parts[1] in ["shares", "creds"]:
            num_loaded = 0
            num_already_seen = 0
            type = "credentials"
            if parts[1] == "shares":
                type = "shares"
            filename = " ".join(parts[2:])
            if os.path.isfile(filename):
                with open(filename) as file:
                    for line in file:
                        if not line.strip():
                            continue
                        if parts[1] == "creds":
                            c = Cred.parse(line.rstrip('\n'))
                            if c:
                                if self.credentials.add(c):
                                    num_loaded += 1
                                else:
                                    num_already_seen += 1
                            else:
                                self.debug("Unknown credential: " + line.rstrip('\n'))
                print("[~] " + str(num_loaded) + " " + type + " have been added",end="")
                if num_already_seen > 0:
                    print(" (" + str(num_already_seen) + " already existed)")
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
            if parts[1] in self.commands.keys() or self.usage[parts[1]] == "":
                print("Help for \"" + parts[1] + "\":\n")
                print("\tInfo: " + self.commands[parts[1]][0] + "\n")
                print("\tUsage: " + self.usage[parts[1]] + "\n")
            else:
                print("Command \"" + parts[1] + "\" not found!")
        else:
            print("Help menu:")
            for cmd in sorted(self.commands.keys()):
                print("\t" + cmd + "\t-\t" + self.commands[cmd][0])

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



class CredBucket:

    def __init__(self):
        self.creds = []

    def add(self, cred):
        exists = False
        for c in self.creds:
            if c == cred:
                exists = True
                break
        if not exists:
            self.creds.append(cred)
            return True
        else:
            return False

    def get_all(self):
        return self.creds

    def get_valid_creds(self):
        valid = []
        for c in self.creds:
            if c.is_valid:
                valid.append(c)
        return valid
    
    def __len__(self):
        return len(self.creds)

    def __getitem__(self, i):
        return self.creds[i]

    def __setitem__(self, i, val):
        self.creds[i] = val

    def __str__(self):
        output_str = "Credential Bucket:\n"
        for c in self.creds:
            output_str += "\t"+str(c)+"\n"

class Cred:

    def __init__(self, domain, username, password, valid=2):
        self.domain = domain
        self.username = username
        self.password = password
        self.valid = valid

    def set_valid(self):
        self.valid = 1

    def set_invalid(self):
        self.valid = 0

    def set_unknown(self):
        self.valid = 2

    def is_valid(self):
        return (self.valid > 0)

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

    def __str__(self):
        type = "Unknown"
        if self.valid == 1:
            type = "Valid"
        elif self.valid == 0:
            type = "Invalid"
        return self.domain + "\\" + self.username + ":" + self.password + "   -   " + type

    def __eq__(self, other):
        return (self.domain == other.domain and self.username == other.username and self.password == other.password)

