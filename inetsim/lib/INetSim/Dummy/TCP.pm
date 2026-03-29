# -*- perl -*-
#
# INetSim::Dummy::TCP - A dummy TCP server
#
# (c)2008-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::Dummy::TCP;

use strict;
use warnings;
use base qw(INetSim::Dummy);



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = INetSim::Config::getConfigParameter("Dummy_TCP_BindPort");  # bind to port
    $self->{server}->{proto}  = 'tcp';                                                      # TCP protocol
    $self->{server}->{user}   = INetSim::Config::getConfigParameter("Default_RunAsUser");   # user to run as
    $self->{server}->{group}  = INetSim::Config::getConfigParameter("Default_RunAsGroup");  # group to run as
    $self->{server}->{setsid} = 0;                                                          # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                                                # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                                       # do not log anything

    $self->{servicename} = INetSim::Config::getConfigParameter("Dummy_TCP_ServiceName");
    $self->{max_childs} = INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = INetSim::Config::getConfigParameter("Default_TimeOut");

    # banner to send
    $self->{Banner} = INetSim::Config::getConfigParameter("Dummy_Banner");
    # time to wait, before the banner will be send
    $self->{Wait} = INetSim::Config::getConfigParameter("Dummy_BannerWait");
}



sub pre_loop_hook {
    my $self = shift;

    $0 = "inetsim_$self->{servicename}";
    INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}



sub pre_server_close_hook {
    my $self = shift;

    INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}



sub fatal_hook {
    my $self = shift;

    INetSim::Log::MainLog("failed!", $self->{servicename});
    exit 0;
}



sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};
    my $stat_success = 0;
    my $line;
    my $got_data = 0;

    INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
    if ($self->{server}->{numchilds} >= $self->{max_childs}) {
        print $client "Maximum number of connections ($self->{max_childs}) exceeded.\n";
        INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{max_childs}) exceeded.", $self->{servicename}, $$);
    }
    else {
        # if dummy_banner_wait > 0 (=enabled)
        if ($self->{Wait}) {
            # wait for client input until $banner_wait timeout
            eval {
                local $SIG{'ALRM'} = sub { die "TIMEOUT1" };
                alarm($self->{Wait});
                while ($line = <$client>) {
                    alarm($self->{Wait});
                    $self->log_recv($line);
                    $stat_success = 1;
                    # one line is enough, get more in the next eval-loop
                    last;
                }
                alarm(0);
            };
            # no input ? -> send banner string ;-)
            if ($@ =~ /TIMEOUT1/) {
                print $client "$self->{Banner}\r\n";
                if ($self->{Banner} ne "") {
                    INetSim::Log::SubLog("[$rhost:$rport] send: $self->{Banner}", $self->{servicename}, $$);
                }
                else {
                    # log cr/lf human readable :-)
                    INetSim::Log::SubLog("[$rhost:$rport] send: <CRLF>", $self->{servicename}, $$);
                }
            }
        }
        # now wait for client input until default timeout
        eval {
            local $SIG{'ALRM'} = sub { die "TIMEOUT2" };
            alarm($self->{timeout});
            while ($line = <$client>) {
                alarm($self->{timeout});
                $self->log_recv($line);
                $stat_success = 1;
            }
            alarm(0);
        };
    }
    if ($@ =~ /TIMEOUT2/) {
        INetSim::Log::SubLog("[$rhost:$rport] disconnect (timeout)", $self->{servicename}, $$);
    }
    else {
        INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    }
    INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
}



sub log_recv {
    my ($self, $string) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (defined $string) {
        $string =~ s/\A[\r\n]+//g;
         INetSim::Log::SubLog("[$rhost:$rport] recv: $string", $self->{servicename}, $$);
    }
}


1;
#
