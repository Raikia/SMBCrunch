SMBCrunch
======

One of the most time consuming tasks as a red teamer is diving into filesystems
and shares, attempting to identify any potentially sensitive information.
SMBCrunch allows a red teamer to quickly identify Windows File Shares in a
network, performs a recursive directory listing of the provided shares, and can
even grab a file from the remote share if it looks like a juicy target.


There are three (3) different tools that work together.  Read all three sections
below to get an idea of how they work together.

---------------------------------

## SMBHunt

Given a file (or gnmap file), SMBHunt finds all the Windows File Shares
associated with the servers provided (if gnmap file is provided, it looks at
servers with port 445 open).  If no credentials are supplied to perform the
check, it will check for null session shares.

**Warning: If your user has access to one share on the server, the script will
show all shares hosted by that server. If a share is listed in this output, it
does _not_ mean you have access to that share.  Use the next tool for that.**

This script does warn you if the credentials you supply fail to avoid locking
out domain accounts.  "-f" switch overrides this protection.

**This script only checks a server using one credential.  This is by design
since the server will respond with a full list of shares if the user has access
to only one share on the system**

### Requirements:

* Linux
* Perl
* smbclient (should be default in Kali)

### Basic Usage:

    ./SMBHunt.pl [-a <account>] -i <file> [-o <output_file>]

### Example Usage:

    ./SMBHunt.pl -a 'testdomain\john:hunter2' -i portscan443.gnmap -o shares_found.txt

### Help to show all available options:

    ./SMBHunt.pl -h

### Arguments:

    -a, --account <string>

> User credentials to test. Usernames are accepted in the form of
'Domain\Username:Password' ('Domain\' is optional)
If no account is given, script checks for null session shares

    -i, --inputFile <file>

> A file of systems separated by a new line, or a gnmap file of a portscan
containing port 445.  Each server with port 445 open will be checked for SMB
shares

    -o, --output <file>
    
> Print results to a file

    -f, --force

> Forces the script to continue even if the domain credential may be
incorrect.

    --noipc

> Do not show IPC shares (IPC$)

    --nohidden

> Do not show hidden shares (C$, IPC$, ADMIN$, etc)


---------------------------------


## SMBList

SMBList will take the output file from "SMBHunt.pl" (or a file of shares
separated by a newline in the format of "\\server\share") and will perform a
recursive directory listing of those shares using the credentials provided.
SMBList will attempt to authenticate to the share until a valid credential is
found from the list provided.  It will then store the directory listings in a
subfolder specified.

This makes the file listing extremely easy to grep through!

** The best result file to use is:  <directory>/ALL_COMBINED_RESULTS.txt **

### Requirements:

* Linux
* Perl
* smbclient (should be default in Kali)

### Basic Usage:

    ./SMBList.pl -c <credential/file> -s <share/file> -o <nonexistent directory>

### Example Usage:

    ./SMBList.pl -c credentials_found.txt -s shares_found.txt -o share_listing -m 150

### Help to show all available options:

    ./SMBList.pl -h

### Arguments:

    -c, --credentials <credential/file>

> A single credential or file of credentails to test. Credentials are accepted
> in the form of 'Domain\Username:Password' separated by a new line (if
> providing a file)

    -s, --shares <share/file>

> A single share or file of shares to test against. Each credential will be
> tested for authorization until a valid one is found. Shares should be in the
> form "\\server\share", separated by a new line (if providing a file)

    -o, --output <nonexistent directory>

> A new directory will be created named this. For protection of output, the
> script cannot be run with this directory existing. It must be a directory that
> does not exist!


    -m, --maxexec <seconds>

> The maximum amonut of time spent dumping any one share, in seconds. Default is
> 300 seconds (5 minutes)

    -f, --force

> Never remove a share from the list if it errors and never remove a credential
> if it gets a logon failed message. If you are using this flag, make sure you
> know what you are doing!  You might lock out accounts if you aren't careful!

    -n, --nocreds

> Don't include credentials in the output.  WARNING: If you use this switch, you
> cannot use the output with the next tool, "SMBGrab.pl".


---------------------------------


## SMBGrab

File listings from SMBList.pl can be pipped into this utility to grab the files
wanted from the shares.  The original listing from SMBList.pl should be
"grepped" before passing to this script, otherwise all files will be downloaded
(which is the equivalent of copying the entire share and is bad)

**This script _requires_ SMBList.pl be pipped in to it.  Look at "Example Usage"
below**

### Requirements:

* Linux
* Perl
* smbclient (should be default in Kali)

### Basic Usage:

    ./SMBGrab.pl [-s <directory>]

### Example Usage:

    grep -i 'password.txt' share_listing/ALL_COMBINED_RESULTS.TXT | ./SMBGrab.pl -s savedfiles

### Help to show all available options:

    ./SMBGrab.pl -h

### Arguments:

If no arguments are supplied, the file is retrieved from the share and displayed
to the user.  It is not saved.

    -s, --savedir <directory>

> A directory to save all the grabbed files to. If this directory does not
> exist, it will be created.  Using this argument saves the files but prevents
> the files from being printed to the screen

    -a, --all

> Read all files pipped in.  Without this switch, the script protects against
> accidentally downloading massive amounts of files by limiting the input to 100
> files.

    -n, --noedit

> This will preserve the files to their original form. If this switch is not
> used, a note will be made at the bottom of each file containing information
> about the file metadata (read/write times, file location in the Share, etc)

    -h, --help

> Display a help menu


---------------------------------


# Contact Information

Feel free to contact me with any changes or feature request!
* https://twitter.com/raikiasec
* raikiasec@gmail.com



