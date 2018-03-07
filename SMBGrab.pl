#!/usr/bin/perl

use strict;
use warnings;


use Getopt::Long;
use Pod::Usage;
use IPC::Open3;
use Time::HiRes qw(usleep);
exit &main();


sub main() {

	print STDERR <<BLOCKOUT

             _____ __  __ ____   _____           _     
            / ____|  \\/  |  _ \\ / ____|         | |    
           | (___ | \\  / | |_) | |  __ _ __ __ _| |__  
            \\___ \\| |\\/| |  _ <| | |_ | '__/ _` | '_ \\ 
            ____) | |  | | |_) | |__| | | | (_| | |_) |
	   |_____/|_|  |_|____/ \\_____|_|  \\__,_|_.__/ 


	                 By Chris King
			   \@raikiasec


BLOCKOUT
	;
	print STDERR "SMBGrab - Chris King\n\n";

	my ($inputRead, $inputSave, $inputNoEdit, $inputHelp, $inputAll);
	$inputSave = $inputNoEdit = $inputHelp = $inputAll = '';

	GetOptions('savedir=s', \$inputSave,
		'noedit', \$inputNoEdit,
		'all', \$inputAll,
		'help', \$inputHelp);
	pod2usage(-verbose => 1) and exit if ($inputHelp);
	unless (not -t STDIN) {
		print STDERR "ERROR!  You must pipe input from a SMBList.pl output!  If you don't know how to use this script, try ./SMBGrab.pl -h\n" and exit;
	}


	my $outputDir = '/tmp/share_read_'.int(rand(10000000));
	$outputDir = $inputSave if ($inputSave ne '');
	my $tempAuthFile = '/tmp/share_read_auth_'.int(rand(10000000)).'.txt';
	if (! -d $outputDir) {
		mkdir $outputDir;
	}
	chdir $outputDir;
	my @stdinLines = <STDIN>;
	if ($inputAll eq '' and scalar(@stdinLines) > 100) {
		print "Alert: You're about to grab ".scalar(@stdinLines)." files!  If you really want to do this, run with the '-a' flag\n" and exit;
	}
	foreach my $line (@stdinLines) {
		chomp $line;
		my ($userpass, $share) = split('\\|:\\|', $line,2);
		my ($username, $password) = split(/:/, $userpass, 2);
		my ($empty, $empty1, $server, $sharename, $file) = split (/\\/, $share,5);
		open (AUTHFILE, '>'.$tempAuthFile) or die("Couldnt create temporary authentication file $tempAuthFile: $!\n");
		print AUTHFILE "username = $username\n";
		print AUTHFILE "password = $password\n";
		close(AUTHFILE);
		my $short_filename = '...'.substr($file, -35);
		printf "%-45s",$short_filename;
		my $unquoted_filename = $file;
		$file =~ s/'/'"'"'/g;
		my @lines = `smbclient -N -A $tempAuthFile '\\\\$server\\$sharename' -c 'get "$file" temp_out.txt' 2> /dev/null`;
		if (scalar(@lines) != 0) {
			if ($lines[0] =~ /NT_STATUS_FILE_IS_A_DIRECTORY/) {
				printf "%-45s\n", "Error: Directory";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_SHARING_VIOLATION/) {
				printf "%-45s\n", "Error: Sharing violation";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_ACCESS_DENIED/) {
				printf "%-45s\n", "Error: Access denied error";
				next;
			}
			elsif ($lines[0] =~ /NT_STATUS_OBJECT_NAME_NOT_FOUND/) {
				printf "%-45s\n","Error: Not found";
				next;
			}
		}
		else {
			printf "%-45s\n", "Success";
		}
		my $new_file_name = $file;
		$new_file_name =~ s/\\/_/g;
		my $new_unquoted_file_name = $unquoted_filename;
		$new_unquoted_file_name =~ s/\\/_/g;
		$new_file_name = $server.'_'.$sharename.'_'.$new_file_name;
		$new_unquoted_file_name = $server.'_'.$sharename.'_'.$new_unquoted_file_name;
		`mv temp_out.txt '$new_file_name'`;
		if ($inputNoEdit eq '') {
			open(NEWFILE, ">>$new_unquoted_file_name");
			print NEWFILE "\n# File from \\\\$server\\$sharename\\$unquoted_filename using $username:$password\n";
			my @data_lines = `smbclient -N -A $tempAuthFile '\\\\$server\\$sharename' -c 'allinfo "$file"' 2> /dev/null`;
			for my $data_line (@data_lines) {
				chomp $data_line;
				print NEWFILE "# $data_line\n"
			}
			print NEWFILE "# END\n";
			close(NEWFILE);
		}
		unlink($tempAuthFile);
		if ($inputSave eq '') {
			open(FILE, "<$new_unquoted_file_name");
			my @output = <FILE>;
			print "\n--------------------------------------\n";
			print "# File from \\\\$server\\$sharename\\$new_unquoted_file_name using $username:$password\n";
			for my $out_line (@output) {
				print $out_line;
			}
			print "\n--------------------------------------\n";
			close(FILE);
		}
	}
	if ($inputSave eq '') {
		if ($outputDir =~ /^\/tmp\/share_read_/) {
			`rm -rf '$outputDir'`;
		}
	}
	return 0;
}
__END__

=head1 Name

SMBGrab.pl

=head1 SYNOPSIS

File listings from SMBList.pl can be pipped into this utility to grab the files
wanted from the shares. The original listing from SMBList.pl should be "grepped"
through before passing it to this script, otherwise all files will be downloaded.

Example:
 cat SMBList_output/ALL_COMBINED_RESULTS.txt | grep 'password.txt' | ./SMBGrab.pl -s savedfiles

=head1 DESCRIPTION

TBD

=head1 Example


=head1 ARGUMENTS

	  If no arguments are used, files grabbed will be displayed to the screen without saving.

=head1 OPTIONS

   -s, --savedir <directory>        A directory to save all the grabbed files to. If this
				    directory does not exist, it will be created.

				    Using this argument saves the files but prevents the files
				    from immediately being printed to the screen.

   -a, --all                        Read all files pipped in. Without this switch, the script
                                    protects against accidentally downloading massive amounts
                                    of files by limiting the input to 100 files. 

   -n, --noedit                     This will preserve the files to their original form.  If
				    this switch is not used, a note will be made at the bottom
				    of each file containing information about the file.

   -h, --help                       Display this menu

=head1 AUTHOR

Chris King

