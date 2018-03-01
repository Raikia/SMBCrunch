#!/usr/bin/perl
use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;

exit main();

my $inputFile = '';
my $accountCredentials = '';
my $outputFile = '';
my $force = 0;
my $helpOption = 0;
my $noipc = 0;
my $nohidden = 0;


sub main {

print STDERR <<BLOCKOUT
             _____ __  __ ____  _    _             _   
            / ____|  \\/  |  _ \\| |  | |           | |  
           | (___ | \\  / | |_) | |__| |_   _ _ __ | |_ 
            \\___ \\| |\\/| |  _ <|  __  | | | | '_ \\| __|
	    ____) | |  | | |_) | |  | | |_| | | | | |_ 
	   |_____/|_|  |_|____/|_|  |_|\\__,_|_| |_|\\__|
	                                                

                            By Chris King
			      \@raikiasec


       Note: This script is for share discovery. It does not guarantee 
             access to the shares it finds.


BLOCKOUT
;


    GetOptions('account=s', \$accountCredentials,
           'input=s', \$inputFile,
           'outputfile=s', \$outputFile,
           'noipc', \$noipc,
           'nohidden', \$nohidden,
           'force', \$force,
           'help', \$helpOption) or pod2usage(-verbose => 1) and exit;
    pod2usage(-verbose => 1) and exit if ($helpOption);
    pod2usage(-verbose => 1, -message => "Error: You must supply a file!\n") and exit unless ($inputFile);
    
    my @ips_with_445;
    if (-e $inputFile) {
    	@ips_with_445 = parse_gnmap($inputFile, 445);
    }
    else {
    	push @ips_with_445, $inputFile;
    }
    my @auth = ('','');
    @auth = split(/:/, $accountCredentials,2) if ($accountCredentials);
    my $temp_file = '/tmp/smb_auth_temp_'.int(rand(10000000)).'.txt';
    open(FILE, '>'.$temp_file) or die $!;
    print FILE "username = $auth[0]\n";
    print FILE "password = $auth[1]\n";
    close(FILE);
    print STDERR "\tNo credentials supplied, looking for null session shares!\n\n" unless ($accountCredentials);
    print STDERR "\tStarting enumerating file shares using domain credential for $auth[0]\n\n" if ($accountCredentials);
    $force = 1 unless ($accountCredentials);
    my $printOut;
    open($printOut, ">$outputFile") or die $! if ($outputFile);
    my $gotError = 0;
    foreach my $a (@ips_with_445) {
        my @output = `smbclient -g -L $a -N -A $temp_file 2> /dev/null`;
        my $startCapture = 0;
        foreach my $b (@output) {
            if ($b =~ /NT_STATUS_LOGON_FAILURE/i and !$force) {
                print STDERR "ERROR!\n\t$a has returned a login failure for this domain account!\n\tContinuing this script may cause the account to become locked out!\n\tIf you want to always ignore this error, re-run with the '-f' flag!\n\n";
                print STDERR "Do you want to always continue during this run? [y/N] ";
                my $input = <STDIN>;
                chomp($input);
                if ($input =~ /y/i) {
                    $force = 1;
                }
                else {
                    $gotError = 1;
                    goto END;
                }
            }

            if ($b =~ /^Disk\|/i or $b =~ /^Printer\|/i) {
                if ($b =~ /^(Disk|Printer)\|(.+)\|(.+)$/) {
                    my $res = $2;
                    unless ($nohidden and $res =~ /\$/)
                    {
                        print $printOut "\\\\$a\\$res\n" if ($printOut);
                        print "\\\\$a\\$res\n";
                    }
                }
            }
            if (!$noipc and $b =~ /^IPC/i) {
                if ($b =~ /^IPC\|(.+)\|(.+)$/) {
                    my $res = $1;
                    unless ($nohidden and $res =~ /\$/)
                    {
                        print $printOut "\\\\$a\\$res\n" if ($printOut);
                        print "\\\\$a\\$res\n";
                    }
                }
            }
        }
    }
    END:
    close($printOut) if ($printOut);
    unlink($temp_file);
    print STDERR "\nDone!\n" unless ($gotError);
}


sub parse_gnmap {
    my $filename = shift;
    my $port = shift;
    my @ips_with_open = ();
    if ($filename =~ '.gnmap') {
        open(FILE, "<$filename") or die $!;
        while (<FILE>) {
            chomp;
            if (/((Ports:)|(,))\s*$port\/open\/tcp/) {
                /Host:\s*(\d+\.\d+\.\d+\.\d+)\s/;
                push @ips_with_open, $1;
            }
        }
        close(FILE);
    }
    else {
        open(FILE, "<$filename") or die $!;
        while (<FILE>) {
            chomp;
            push @ips_with_open, $_;
        }
    }
    return @ips_with_open;
}

__END__

=head1 Name

SMBHunt.pl

=head1 SYNOPSIS

    Given a gnmap file, SMBHunt finds all the file system shares associated with
    the servers with port 445 open.  If no credentials are supplied, it checks for
    null session shares.

    Warning: All shares are listed in the output! This does not mean that the
    credentials you supplied have access to that specific share!

=head1 DESCRIPTION

    TBD

=head1 ARGUMENTS

   -a, --account <string>       User credentials to test.  Usernames are
                                accepted in the form of "DOMAIN\USERNAME:PASSWORD"
                                ("DOMAIN\" is optional) (Optional argument: If no
                                account is given, script checks for null session shares)

   -i, --input <file or word>   A system or file of systems separated by a new line, or a
                                gnmap file of a portscan containing port 445.  Each 
                                server with port 445 open will be checked for file system
                                shares

=head1 OPTIONS

   -o, --output <file>          Print results to a file

   -f, --force                  Forces the script to continue even if the domain
                                credential may be incorrect

   --noipc                      Do not show IPC shares

   --nohidden                   Do not show hidden shares (C$, IPC$, ADMIN$, etc)

=head1 AUTHOR

Chris King

