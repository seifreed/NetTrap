# -*- perl -*-
#
# INetSim::Log - INetSim logging
#
# (c)2007-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::Log;

use strict;
use warnings;
use Fcntl ':mode';

my $mainlogfilename;
my $sublogfilename;
my $debuglogfilename;
my $DEBUG = 0;
my $SID = undef;


sub init {
    my $dummy = INetSim::Config::getConfigParameter("MainLogfileName");
    $dummy =~ /\A(.*)\z/; # evil untaint!
    $mainlogfilename = $1;
    $dummy = INetSim::Config::getConfigParameter("SubLogfileName");
    $dummy =~ /\A(.*)\z/; # evil untaint!
    $sublogfilename = $1;
    $dummy = INetSim::Config::getConfigParameter("DebugLogfileName");
    $dummy =~ /\A(.*)\z/; # evil untaint!
    $debuglogfilename = $1;
    my $group = INetSim::Config::getConfigParameter("Default_RunAsGroup");
    $group =~ /\A(.*)\z/; # evil untaint!
    $group = $1;

    # check if MainLogfile exists
    if (! -f $mainlogfilename) {
        # if not, create it
        print STDOUT "Main logfile '$mainlogfilename' does not exist. Trying to create it...\n";
        if (open (MLOG, ">$mainlogfilename")) {
            print STDOUT "Main logfile '$mainlogfilename' successfully created.\n";
            close MLOG;
            chmod 0660, $mainlogfilename;
            my $gid = getgrnam($group);
            if (! defined $gid) {
                INetSim::error_exit("Unable to get GID for group '$group'");
            }
            chown -1, $gid, $mainlogfilename;
        }
        else {
            INetSim::error_exit("Unable to create main logfile '$mainlogfilename': $!");
        }
    }
    else {
        # check ownership and permissions
        my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $mainlogfilename;
        my $grpname = getgrgid $gid;
        # check group owner
        if ($grpname ne $group) {
            INetSim::error_exit("Group owner of main logfile '$mainlogfilename' is not '$group' but '$grpname'");
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            INetSim::error_exit("No group r/w permissions on main logfile '$mainlogfilename'");
        }
    }


    # check if SubLogfile exists
    if (! -f $sublogfilename) {
        # if not, create it
        print STDOUT "Sub logfile '$sublogfilename' does not exist. Trying to create it...\n";
        if (open (MLOG, ">$sublogfilename")) {
            print STDOUT "Sub logfile '$sublogfilename' successfully created.\n";
            close MLOG;
            chmod 0660, $sublogfilename;
            my $gid = getgrnam($group);
            if (! defined $gid) {
                INetSim::error_exit("Unable to get GID for group '$group'");
            }
            chown -1, $gid, $sublogfilename;
        }
        else {
            INetSim::error_exit("Unable to create sub logfile '$sublogfilename': $!");
        }
    }
    else {
        # check ownership and permissions
        my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $sublogfilename;
        my $grpname = getgrgid $gid;
        # check group owner
        if ($grpname ne $group) {
            INetSim::error_exit("Group owner of sub logfile '$sublogfilename' is not '$group' but '$grpname'");
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            INetSim::error_exit("No group r/w permissions on sub logfile '$sublogfilename'");
        }
    }


    # check if DebugLogfile exists
    if (! -f $debuglogfilename) {
        # if not, create it
        print STDOUT "Debug logfile '$debuglogfilename' does not exist. Trying to create it...\n";
        if (open (MLOG, ">$debuglogfilename")) {
            print STDOUT "Debug logfile '$debuglogfilename' successfully created.\n";
            close MLOG;
            chmod 0660, $debuglogfilename;
            my $gid = getgrnam($group);
            if (! defined $gid) {
                INetSim::error_exit("Unable to get GID for group '$group'");
            }
            chown -1, $gid, $debuglogfilename;
        }
        else {
            INetSim::error_exit("Unable to create debug logfile '$debuglogfilename': $!");
        }
    }
    else {
        # check ownership and permissions
        my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $debuglogfilename;
        my $grpname = getgrgid $gid;
        # check group owner
        if ($grpname ne $group) {
            INetSim::error_exit("Group owner of debug logfile '$debuglogfilename' is not '$group' but '$grpname'");
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            INetSim::error_exit("No group r/w permissions on debug logfile '$debuglogfilename'");
        }
    }

    $DEBUG = INetSim::Config::getConfigParameter("Debug");
}



sub MainLog{
    my $msg = shift || return 0;
    my $service = shift || "main";
    $msg =~ s/[\r\n]*\z//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime();
    my $date = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (MLOG, ">>$mainlogfilename")) {
        INetSim::error_exit("Unable to open main logfile '$mainlogfilename': $!");
    }

    select MLOG;
    $| = 1;
    if ($service ne "main") {
        print MLOG "[$date]    * $service $msg\n";
        $msg =~ s/failed\!/\033\[31\;1mfailed\!\033\[0m/;
        print STDOUT "  * $service - $msg\n";
    }
    else {
        print MLOG "[$date]  $msg\n";
        $msg =~ s/failed\!/\033\[31\;1mfailed\!\033\[0m/;
        print STDOUT "$msg\n";
    }
    close MLOG;
}



sub SubLog{
    my ($msg, $service, $cpid) = @_;
    ($msg && $service && $cpid) or return;
    $msg =~ s/[\r\n]*\z//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime(INetSim::FakeTime::get_faketime());
    my $fakedate = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (SLOG, ">>$sublogfilename")) {
        INetSim::error_exit("Unable to open sub logfile '$sublogfilename': $!");
    }
    select SLOG;
    $| = 1;
    # replace non-printable characters with "."
    $msg =~ s/([^\x20-\x7e])/\./g;
    (!$SID) && ($SID = INetSim::Config::getConfigParameter("SessionID"));
    print SLOG "[$fakedate] [$SID] [$service $cpid] $msg\n";
    close SLOG;
}



sub DebugLog{
    ($DEBUG) or return;
    my ($msg, $service, $cpid) = @_;
    ($msg && $service && $cpid) or return;
    $msg =~ s/[\r\n]*\z//g;
    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$ydat,$isdst) = localtime(INetSim::FakeTime::get_faketime());
    my $fakedate = sprintf "%4d-%02d-%02d %02d:%02d:%02d", $year+1900,$mon+1,$mday,$hour,$min,$sec;

    if (! open (DLOG, ">>$debuglogfilename")) {
        INetSim::error_exit("Unable to open debug logfile '$debuglogfilename': $!");
    }
    select DLOG;
    $| = 1;
    # replace non-printable characters with "."
    $msg =~ s/([^\x20-\x7e])/\./g;
    (!$SID) && ($SID = INetSim::Config::getConfigParameter("SessionID"));
    print DLOG "[$fakedate] [$SID] [$service $cpid] $msg\n";
    close DLOG;
}


1;
#
