# -*- perl -*-
#
# INetSim - An internet simulation framework
#
# (c)2007-2020 Matthias Eckert, Thomas Hungenberg
#
#############################################################

my $VERSION = "INetSim 1.3.2 (2020-05-19)";

package INetSim;

use strict;
use warnings;
use POSIX;
# modules to use
use INetSim::CommandLine;
use INetSim::Config;
use INetSim::Log;
use INetSim::FakeTime;
use INetSim::Chargen::TCP;
use INetSim::Chargen::UDP;
use INetSim::Daytime::TCP;
use INetSim::Daytime::UDP;
use INetSim::Discard::TCP;
use INetSim::Discard::UDP;
use INetSim::Echo::TCP;
use INetSim::Echo::UDP;
use INetSim::Quotd::TCP;
use INetSim::Quotd::UDP;
use INetSim::Time::TCP;
use INetSim::Time::UDP;
use INetSim::HTTP;
use INetSim::Ident;
use INetSim::NTP;
use INetSim::SMTP;
use INetSim::POP3;
use INetSim::DNS;
use INetSim::TFTP;
use INetSim::Report;
use INetSim::Finger;
use INetSim::Dummy::TCP;
use INetSim::Dummy::UDP;
use INetSim::FTP;
use INetSim::Syslog;
use INetSim::IRC;


#############################################################
# Local variables

my $PPID = $$;   # Parent PID
my @childs = (); # Child PIDs


#############################################################
# Child process handling
#
sub fork_services {
    my @services_to_start = INetSim::Config::getServicesToStart();
    foreach (@services_to_start) {
        my $pid = fork();
        if ($pid) {
            # we are the parent process
            push(@childs, $pid);
        }
        elsif ($pid == 0){
            # we are the child process
            if(/\Adns\z/) {
                INetSim::DNS::dns();
            }
            elsif(/\Asmtp\z/) {
                INetSim::SMTP->run;
            }
            elsif(/\Asmtps\z/) {
                INetSim::SMTP->new({ SSL => 1 })->run;
            }
            elsif(/\Apop3\z/) {
                INetSim::POP3->run;
            }
            elsif(/\Apop3s\z/) {
                INetSim::POP3->new({ SSL => 1 })->run;
            }
            elsif(/\Ahttp\z/) {
                INetSim::HTTP->run;
            }
            elsif(/\Ahttps\z/) {
                INetSim::HTTP->new({ SSL => 1 })->run;
            }
            elsif(/\Antp\z/) {
                INetSim::NTP->run;
            }
            elsif(/\Atime_tcp\z/) {
                INetSim::Time::TCP->run;
            }
            elsif(/\Atime_udp\z/) {
                INetSim::Time::UDP->run;
            }
            elsif(/\Adaytime_tcp\z/) {
                INetSim::Daytime::TCP->run;
            }
            elsif(/\Adaytime_udp\z/) {
                INetSim::Daytime::UDP->run;
            }
            elsif(/\Aident\z/) {
                INetSim::Ident->run;
            }
            elsif(/\Aecho_tcp\z/) {
                INetSim::Echo::TCP->run;
            }
            elsif(/\Aecho_udp\z/) {
                INetSim::Echo::UDP->run;
            }
            elsif(/\Adiscard_tcp\z/) {
                INetSim::Discard::TCP->run;
            }
            elsif(/\Adiscard_udp\z/) {
                INetSim::Discard::UDP->run;
            }
            elsif(/\Achargen_tcp\z/) {
                INetSim::Chargen::TCP->run;
            }
            elsif(/\Achargen_udp\z/) {
                INetSim::Chargen::UDP->run;
            }
            elsif(/\Aquotd_tcp\z/) {
                INetSim::Quotd::TCP->run;
            }
            elsif(/\Aquotd_udp\z/) {
                INetSim::Quotd::UDP->run;
            }
            elsif(/\Atftp\z/) {
                INetSim::TFTP->run;
            }
            elsif(/\Afinger\z/) {
                INetSim::Finger->run;
            }
            elsif(/\Adummy_tcp\z/) {
                INetSim::Dummy::TCP->run;
            }
            elsif(/\Adummy_udp\z/) {
                INetSim::Dummy::UDP->run;
            }
            elsif(/\Aftp\z/) {
                INetSim::FTP->run;
            }
            elsif(/\Aftps\z/) {
                INetSim::FTP->new({ SSL => 1 })->run;
            }
            elsif(/\Asyslog\z/) {
                INetSim::Syslog->run;
            }
            elsif(/\Airc\z/) {
                INetSim::IRC->run;
            }
            elsif(/\Aircs\z/) {
                INetSim::IRC->run( SSL => 1 );
            }
        }
        else {
            error_exit("Could not fork: $!", 1);
        }
    }
    sleep 1;
}


sub handle_pid {
    my $cmd = shift;
    my $pidfile = INetSim::CommandLine::getCommandLineOption("pidfile");

    $pidfile =~ /(.*)/; # evil untaint
    $pidfile = $1;
    if ($cmd eq "create") {
        if (-f $pidfile) {
            print STDOUT "PIDfile '$pidfile' exists - INetSim already running?\n";
            exit 1;
        }
        else {
            if (! open (PIDFILE, "> $pidfile")) {
                print STDOUT "Unable to open PIDfile for writing: $!\n";
                exit 1;
            }
            print PIDFILE $PPID;
            close PIDFILE;
        }
    }
    elsif ($cmd eq "remove") {
        if (-f $pidfile) {
            unlink $pidfile;
        }
        else {
            print STDOUT "Hmm, PIDfile '$pidfile' not found (but, who cares?)\n";
        }
    }
}


sub auto_faketime {
    if (INetSim::Config::getConfigParameter("Faketime_AutoDelay") > 0) {
        my $pid = fork();
        if ($pid) {
            # we are the parent process
            push(@childs, $pid);
        }
        elsif ($pid == 0){
            # we are the child process
            INetSim::FakeTime::auto_faketime();
        }
    }
}


sub redirect_packets {
    if (INetSim::Config::getConfigParameter("Redirect_Enabled")) {
        # check for linux
        if ($^O !~ /linux/i) {
            INetSim::Log::MainLog("failed! Error: Sorry, the Redirect module does not support this operating system!", "redirect");
            return 0;
        }
        # check for nfqueue library
        eval {
            eval "use nfqueue; 1" or die;
        };
        if ($@) {
            INetSim::Log::MainLog("failed! Error: Sorry, this module requires the perl nfqueue-bindings!", "redirect");
            return 0;
        }
        # check for redirect module
        eval {
               eval "use INetSim::Redirect; 1" or die;
        };
        if ($@) {
            INetSim::Log::MainLog("failed! Error: $@", "redirect");
            return 0;
        }
        my $pid = fork();
        if ($pid) {
            # we are the parent process
            push(@childs, $pid);
        }
        elsif ($pid == 0){
            # we are the child process
            INetSim::Redirect::run();
        }
    }
}


sub rest_in_peace {
    my $count = @childs;
    my $i;

    for ($i = 0; $i < $count; $i++) {
        waitpid(-1,&WNOHANG);
        if (! (kill (0, $childs[$i]))) {
            splice (@childs, $i, 1);
            $count = @childs;
            $i--;
        }
    }
}


sub wait_pids {
    wait();
    foreach (@childs){
        waitpid($_, 0);
    }
}


sub kill_pids {
    foreach (@childs){
        kill("TERM", $_);
        waitpid($_, 0);
    }
}


sub error_exit {
    my $msg = shift;
    if (! defined $msg) {
        $msg = "Unknown error";
    }
    my $exitcode = shift;
    if (! defined $exitcode) {
        $exitcode = 1;
    }
    elsif (($exitcode !~ /\A[\d]{1,3}\z/) || (int($exitcode) < 0) || (int($exitcode > 255))) {
        print STDOUT "Illegal exit code!\n";
        $exitcode = 1;
    }

    print STDOUT "Error: $msg.\n";

    kill_pids();
    wait_pids();
    handle_pid("remove");

    exit 1;
}


#############################################################
# Main
#

sub main {
    # Parse commandline options
    INetSim::CommandLine::parse_options();

    # Check command line option 'help'
    if (INetSim::CommandLine::getCommandLineOption("help")) {
        print STDOUT << "EOF";
$VERSION by Matthias Eckert & Thomas Hungenberg

Usage: $0 [options]

Available options:
  --help                         Print this help message.
  --version                      Show version information.
  --config=<filename>            Configuration file to use.
  --log-dir=<directory>          Directory logfiles are written to.
  --data-dir=<directory>         Directory containing service data.
  --report-dir=<directory>       Directory reports are written to.
  --bind-address=<IP address>    Default IP address to bind services to.
                                 Overrides configuration option 'default_bind_address'.
  --max-childs=<num>             Default maximum number of child processes per service.
                                 Overrides configuration option 'default_max_childs'.
  --user=<username>              Default user to run services.
                                 Overrides configuration option 'default_run_as_user'.
  --faketime-init-delta=<secs>   Initial faketime delta (seconds).
                                 Overrides configuration option 'faketime_init_delta'.
  --faketime-auto-delay=<secs>   Delay for auto incrementing faketime (seconds).
                                 Overrides configuration option 'faketime_auto_delay'.
  --faketime-auto-incr=<secs>    Delta for auto incrementing faketime (seconds).
                                 Overrides configuration option 'faketime_auto_increment'.
  --session=<id>                 Session id to use. Defaults to main process id.
  --pidfile=<filename>           Pid file to use. Defaults to '/var/run/inetsim.pid'.

EOF
;
        exit 0;
    }
    elsif (INetSim::CommandLine::getCommandLineOption("version")) {
        print STDOUT "$VERSION by Matthias Eckert & Thomas Hungenberg\n";
        exit 0;
    }


    # Check if we are running with root privileges (EUID 0)
    if ( $> != 0 ) {
        print STDOUT "Sorry, this program must be started as root!\n";
        exit 1;
    }

    # Check if group "inetsim" exists on system
    my $group = INetSim::Config::getConfigParameter("Default_RunAsGroup");
    $group =~ /\A(.*)\z/; # evil untaint!
    $group = $1;    
    my $gid = getgrnam($group);
    if (! defined $gid) {
        print STDOUT "No such group '$group' configured on this system!\n";
        print STDOUT "Please create group and start again. See documentation for more information.\n";
        exit 1;
    }

    print STDOUT "$VERSION by Matthias Eckert & Thomas Hungenberg\n";

    # create pidfile
    handle_pid("create");

    # Parse configuration file
    INetSim::Config::parse_config();

    # Check if there are services to start configured, else exit
    if (! scalar(INetSim::Config::getServicesToStart())) {
        INetSim::Log::MainLog("No services to start configured. Exiting.");
        handle_pid("remove");
        exit 0;
    }

    # ignore some signal handlers during startup
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'HUP'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';

    INetSim::Log::MainLog("=== INetSim main process started (PID $PPID) ===");
    INetSim::Log::MainLog("Session ID:     " . INetSim::Config::getConfigParameter("SessionID"));
    INetSim::Log::MainLog("Listening on:   " . INetSim::Config::getConfigParameter("Default_BindAddress"));
    INetSim::Log::MainLog("Real Date/Time: " . strftime "%Y-%m-%d %H:%M:%S", localtime);
    INetSim::Log::MainLog("Fake Date/Time: " . (strftime "%Y-%m-%d %H:%M:%S", localtime(INetSim::FakeTime::get_faketime())). " (Delta: " . INetSim::Config::getConfigParameter("Faketime_Delta") . " seconds)");
    INetSim::Log::MainLog(" Forking services...");
    fork_services();
    auto_faketime();
    redirect_packets();

    if ($$ == $PPID) {
        $0 = 'inetsim_main';
        sleep 2;
        # reap zombies ;-)
        rest_in_peace();
        INetSim::Log::MainLog(" done.");
        INetSim::Log::MainLog("Simulation running.");
        # catch up some signalhandlers for the parent process
        local $SIG{'INT'} = sub {kill_pids();};
        local $SIG{'HUP'} = sub {kill_pids();};
        local $SIG{'TERM'} = sub {kill_pids();};
        wait_pids();
        INetSim::Log::MainLog("Simulation stopped.");

        # create report
        if (INetSim::Config::getConfigParameter("Create_Reports")) {
            INetSim::Report::GenReport();
        }

        INetSim::Log::MainLog("=== INetSim main process stopped (PID $PPID) ===");
        INetSim::Log::MainLog(".");
    }

    # delete pidfile
    handle_pid("remove");
    exit 0;
}


1;
#
