#!/usr/bin/perl

# SMBList
# By Chris King (chris.king@mandiant.com)

use strict;
use warnings;

use Getopt::Long;
use Pod::Usage;
use IPC::Open3;
use Time::HiRes qw(usleep);
exit main();



sub main {
	print STDERR <<BLOCKOUT

             _____ __  __ ____  _      _     _   
            / ____|  \\/  |  _ \\| |    (_)   | |  
           | (___ | \\  / | |_) | |     _ ___| |_ 
            \\___ \\| |\\/| |  _ <| |    | / __| __|
 	    ____) | |  | | |_) | |____| \\__ \\ |_ 
	   |_____/|_|  |_|____/|______|_|___/\\__|
	                     

                        By Chris King
			 \@raikiasec

BLOCKOUT
	;                                                 

	my ($inputCreds, $inputShares, $inputOutput, $inputMaxExec, $inputHelp, $inputForce, $inputNoCreds);
	$inputCreds = $inputShares = $inputOutput = $inputMaxExec = $inputHelp = $inputForce = $inputNoCreds = '';
	$inputMaxExec = 300;
	my $credsSeparator = ':';
	GetOptions('credentials=s', \$inputCreds,
		'shares=s', \$inputShares,
		'output=s', \$inputOutput,
		'maxexec=s', \$inputMaxExec,
		'force', \$inputForce,
		'nocreds', \$inputNoCreds,
		'help', \$inputHelp);
	pod2usage(-verbose => 1) and exit if ($inputHelp);
	if (not -t STDIN and $inputShares eq '') {
		$inputShares = '..';
	}
	pod2usage(-verbose => 1, -message => "\tError: You must supply at least one share to test access to and an output directory!\n") and exit if ($inputShares eq '' or $inputOutput eq '');

	my @accounts = ();
	my @shares = ();
	if (-e $inputCreds) {
		open(my $fh, '<', $inputCreds) or pod2usage(-verbose => 1, -message => "Error: $0 - open '$inputCreds' - $!\n") and exit;
		@accounts = <$fh>;
		chomp @accounts;
		@accounts = grep { print "\tCred '$_' did not have the credential separator '$credsSeparator' in it. Omitting...\n" and 0 unless(index($_,$credsSeparator)>-1); 1;} @accounts;
		close($fh);
	}
	else {
		if ($inputCreds eq '') {
			print "\tNo account credentials given!  Attempting null share access\n";
			$inputCreds = ':';
		}
		pod2usage(-verbose => 1, -message =>  "\tError: '$inputCreds', the account to be used, did not have '$credsSeparator' in it to separate username and password! Attempting null session\n") if (index($inputCreds,$credsSeparator) == -1);
		push @accounts, $inputCreds;
	}

	if ($inputShares eq '..') {
		print "\tPipped input detected!  Using piped data as input for shares\n";
		my @stdinShares = <STDIN>;
		foreach (@stdinShares) {
			chomp;
			if (!/^\\\\.*\\.*$/) {
				print "\tShare '$_' is not in the valid format of \\\\server\\share. Omitting...\n";
			}
			else {
				push @shares, $_;
			}
		}
	}
	elsif (-e $inputShares) {
		open(my $fh, '<', $inputShares) or pod2usage(-verbose => 1, -message => "Error: $0 - open '$inputShares' - $!\n") and exit;
		my @temp_shares = <$fh>;
		chomp @temp_shares;
		foreach my $check_share(@temp_shares) {
			if ($check_share !~ /^\\\\.*\\.*$/) {
				print "\tShare '$check_share' is not in the valid format of \\\\server\\share.  Omitting...\n";
			}
			else {
				push @shares, $check_share;
			}
		}
		close($fh);
		print "\tNo valid shares were found in this file!  Cannot continue!\n" and exit if (scalar(@shares) == 0);
	}
	else {
		print "\tShare '$inputShares' is not in the valid format of \\\\server\\share.  Cannot continue!\n" and exit if ($inputShares !~ /^\\\\.*\\.*$/);
		push @shares, $inputShares;
	}

	mkdir "$inputOutput" or die "Output directory already exists\n";
	chdir "$inputOutput";
	my $fh_all_results;
	open($fh_all_results, ">ALL_COMBINED_RESULTS.txt") or die "Could not create a new file! $!\n";
	my $tempAuthFile = '/tmp/SMBList_auth_'.int(rand(100000000)).'.txt';
	printf "%-35s %-35s %-35s %-35s\n", 'Share', 'Username', 'Password', 'Progress';
	print "--------------------------------------------------------------------------------------------------------------------------------\n";
	foreach my $share (@shares) {
		my $validCredFound = 0;
		foreach my $account (@accounts) {
			next if ($validCredFound);
			my ($username, $password) = split(/$credsSeparator/, $account, 2);
			open(AUTHFILE, '>'.$tempAuthFile);
			print AUTHFILE 'username = '.$username."\n";
			print AUTHFILE 'password = '.$password."\n";
			close(AUTHFILE);
			printf '%-35s %-35s %-35s %-35s', $share, $username, $password, 'Running...';
			#print "smbclient -N -A '$tempAuthFile' '$share' -c 'recurse;dir' 2>&1 > temporary_running_file.txt";
			#die;
            $share =~ s/'/'\\''/g;
			my $smbclient_cmd = `timeout $inputMaxExec smbclient -N -A '$tempAuthFile' '$share' -c 'recurse;dir' 2>&1 > temporary_running_file.txt`;
			unlink($tempAuthFile);
			print "\b"x35;
			printf "%-35s", "Cleaning....";
			my $tempFile = `cat temporary_running_file.txt`;
			$tempFile = "NO_DATA\n" if ($tempFile =~ /^\s*$/);
			my @lines = split "\n", $tempFile;
			unless ($lines[0] =~ /BAD_NETWORK_NAME/ or $lines[0] =~ /ACCESS_DENIED/ or $lines[0] =~ /LOGON_FAILURE/ or $lines[0] =~ /NT_STATUS_UNSUCCESSFUL/ or $lines[0] =~ /INVALID_DEVICE_REQUEST/ or $lines[0] =~ /ACCOUNT_LOCKED_OUT/ or $lines[0] =~ /WRONG_PASSWORD/ or $lines[0] =~ /NETWORK_UNREACHABLE/ or $lines[0] =~ /NO_DATA/ or $lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/ or $lines[0] =~ /NT_STATUS_NO_LOGON_SERVERS/) {
				my $newShareFileName = $share;
				$newShareFileName =~ s/\\\\//g;
				$newShareFileName =~ s/\\/_/g;
				$newShareFileName =~ s/\//-/g;
				my $currentPath = "";
				my $fh_share_file;
				open($fh_share_file, ">$newShareFileName") or die "Could not save a new file! $!\n";
				print $fh_share_file "# SHARE INFO: ".$lines[0]."\n\n";
				foreach my $line (@lines) {
					if ($line =~ /^\\.*/) {
						$currentPath = $line;
						next;
					}
					$line =~ /\s{2}(.*)\s+\w+\s+\d+\s+\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4}$/;
					unless ($1) {
						next;
					}
					my $filename = "$1";
					$filename =~ s/\s+$//;
					next if ($filename =~ /^\.{0,2}$/);
					if ($inputNoCreds eq '') {
						print $fh_share_file "$username:$password|:|$share$currentPath\\$filename\n";
						print $fh_all_results "$username:$password|:|$share$currentPath\\$filename\n";
					}
					else {
						print $fh_share_file "$share$currentPath\\$filename\n";
						print $fh_all_results "$share$currentPath\\$filename\n";
					}
				}
				close($fh_share_file);
				$validCredFound = 1;
				print "\b"x35;
				printf "%-35s\n", "Success!";
			}
			else {
				print "\b"x35;
				printf("%-35s\n", "Access Denied") if ($lines[0] =~ /ACCESS_DENIED/);
				printf("%-35s\n", "Logon Failure") if ($lines[0] =~ /LOGON_FAILURE/);
				printf("%-35s\n", "Bad Network Name") if ($lines[0] =~ /BAD_NETWORK_NAME/);
				printf("%-35s\n", "Unsuccessful Connection") if ($lines[0] =~ /NT_STATUS_UNSUCCESSFUL/);
				printf("%-35s\n", "Invalid Device") if ($lines[0] =~ /INVALID_DEVICE_REQUEST/);
				printf("%-35s\n", "Account Locked") if ($lines[0] =~ /ACCOUNT_LOCKED_OUT/);
				printf("%-35s\n", "Wrong Password") if ($lines[0] =~ /WRONG_PASSWORD/);
				printf("%-35s\n", "No Network Connection") if ($lines[0] =~ /NETWORK_UNREACHABLE/);
				printf("%-35s\n", "Host is not available") if ($lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/);
				printf("%-35s\n", "No Logon Servers") if ($lines[0] =~ /NT_STATUS_NO_LOGON_SERVERS/);
				printf("%-35s\n", "No Data") if ($lines[0] =~ /NO_DATA/);
				if ($inputForce and ($lines[0] =~ /LOGON_FAILURE/ or $lines[0] =~ /ACCOUNT_LOCKED_OUT/ or $lines[0] =~ /WRONG_PASSWORD/)) {
					# POP @accounts HERE
					#@accounts = grep { $_ != $account } @accounts;
				}
				if ($inputForce and ($lines[0] =~ /NT_STATUS_UNSUCCESSFUL/ or $lines[0] =~ /INVALID_DEVICE_REQUEST/ or $lines[0] =~ /NETWORK_UNREACHABLE/ or $lines[0] =~ /NT_STATUS_HOST_UNREACHABLE/)) {
					# POP @shares HERE
					#@shares = grep { $_ != $share } @shares;
				}
			}
			`rm -f temporary_running_file.txt &> /dev/null`;
			usleep(3000);
		}
	}
}

=head1 Name

SMBList.pl

=head1 SYNOPSIS

Dump a recursive directory listing of all shares identified in an environment.  You
can supply a list of credentials to test.  You can then grep through the resulting
files to identify any potentially good files to target.

=head1 DESCRIPTION

TBD

=head1 ARGUMENTS

   -c, --credentials <word/file>    A word or file of user credentials to test.
				    Usernames are accepted in the form of 
				    "DOMAIN\USERNAME:PASSWORD"

				    ("DOMAIN\" is optional)
				    (Username:Password delimiter is configurable)

   -s, --shares <word/file>         A word or file of shares to test against.
				    Each credential will be tested against each
				    of these shares until a valid one is found.
				    Shares should be in the form "\\server\share"

   -o, --output <word>              A new directory will be created named this. For
				    protection of output, the script can not be run
				    with this directory existing.  It must be a 
				    directory that does not yet exist!

=head1 OPTIONS

   -m, --maxexec <number>           The maxiumum amount of time spent dumping any
				    one share, in seconds.  Default is 300 seconds
				    (5 minutes)          

   -f, --force                      Never remove a share from the list if it errors,
				    and never remove a credential if it gets a logon
				    failed message. If you use this flag, make sure
				    you know what you are doing! You might lock out
				    accounts if you aren't careful!

   -n, --nocreds		    Don't include credentials in the output.
                                    WARNING: If you use this switch, you cannot use 
                                    the output with ./SMBGrab.pl

=head1 AUTHOR

Chris King

