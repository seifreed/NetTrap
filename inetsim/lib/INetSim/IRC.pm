# -*- perl -*-
#
# INetSim::IRC - A fake IRC server
#
# RFC 1459 - Internet Relay Chat Protocol
#
# (c)2009-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::IRC;

use strict;
use warnings;
use POSIX;
use IO::Socket;
use IO::Select;


my %CONN;
my %NICK;
my %USER;
my %HOST;
my %CHAN;



sub loop {
    my $self = shift;
    my $socket = $self->{server}->{socket};
    my $select = $self->{server}->{select};
    my $client;

    while (1) {
        my @can_read = $select->can_read(0.01);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_read) {
            if ($client == $socket) {
                $self->_accept;
                next;
            }
            $self->{server}->{client} = $client;
            $self->process_request;
        }
        my @can_write = $select->can_write(0.01);
        $self->{number_of_clients} = int($select->count());
        foreach $client (@can_write) {
            $self->{server}->{client} = $client;
            #$self->check_timeout();
        }
    }
}



sub send_initial_response {
    my $self = shift;
    my $client = $self->{server}->{client};

    my $now = INetSim::FakeTime::get_faketime();
    $CONN{$client}->{connected} = $now;
    $CONN{$client}->{last_send} = $now;
    $CONN{$client}->{host} = $client->peerhost;
    $CONN{$client}->{port} = $client->peerport;
    $self->send_("NOTICE AUTH :*** Welcome to $self->{hostname}");
    $self->send_("NOTICE AUTH :*** Looking up your hostname");
    $self->send_("NOTICE AUTH :*** Checking Ident");
    $self->send_("NOTICE AUTH :*** No ident response");
    $self->send_("NOTICE AUTH :*** Found your hostname");
}



sub _accept {
    my $self = shift;

    # accept the new connection
    my $client = $self->{server}->{socket}->accept;
    (defined $client) or return 0;
    ($client->connected) or return 0;
    $self->{server}->{client} = $client;

    # add the new handle to IO::Select
    $self->{server}->{select}->add($client);
    if ($self->{server}->{select}->exists($client)) {
        $self->slog_("connect");
        $self->send_initial_response();
        return 1;
    }
    else {
        $self->slog_("connect");
        if ($self->{number_of_clients} >= $self->{maxchilds}) {
            $self->send_("ERROR :Closing Link: " . $client->peerhost . " (Maximum number of connections ($self->{maxchilds}) exceeded)");
        }
        else {
            $self->send_("ERROR :Closing Link: " . $client->peerhost . " (Internal server error)");
        }
        $self->slog_("disconnect");
        $client->close;
        return 0;
    }
}


sub register_connection {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;

    $CONN{$client} = {  connected        => 0,
                        host             => undef,
                        port             => undef,
                        ssl              => undef,
                        last_recv        => 0,
                        last_send        => undef,
                        last_ping_send   => 0,
                        last_pong_recv   => 0,
                        retries          => 2,
                        registered       => 0,
                        pass             => undef,
                        user             => undef,
                        nick             => undef,
                        realname         => undef,
                        channels         => undef,
                        modes            => undef
                    };
}


sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;
#    my $registered = $CONN{$client}->{registered};
#    my $user = $CONN{$client}->{user};
#    my $nick = $CONN{$client}->{nick};

    my $line = <$client>;
    if (!defined $line) {
        $self->QUIT;
        return;
    }
    $line =~ s/[\r\n]+\z//;
    ($line) or return;
    $self->slog_("recv: $line");
    # update timestamp
    $CONN{$client}->{last_recv} = INetSim::FakeTime::get_faketime();
    # process request below...
    my ($user, $nick, $host, $command, $params) = $self->split_messageparts($line);
    (defined $command && $command) or return;
    #
    if ($command =~ /\APASS\z/i) {
        $self->PASS($user, $nick, $host, $params);
    }
    elsif ($command =~ /\ANICK\z/i) {
        $self->NICK($user, $nick, $host, $params);
    }
    elsif ($command =~ /\AUSER\z/i) {
        $self->USER($user, $nick, $host, $params);
    }
#    elsif ($command =~ /\ASERVER\z/i) {
#        $self->SERVER($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AOPER\z/i) {
#        $self->OPER($user, $nick, $host, $params);
#    }
    elsif ($command =~ /\AQUIT\z/i) {
        $self->QUIT($user, $nick, $host, $params);
    }
#    elsif ($command =~ /\ASQUIT\z/i) {
#        $self->SQUIT($user, $nick, $host, $params);
#    }
    elsif ($command =~ /\AJOIN\z/i) {
        $self->JOIN($user, $nick, $host, $params);
    }
    elsif ($command =~ /\APART\z/i) {
        $self->PART($user, $nick, $host, $params);
    }
    elsif ($command =~ /\AMODE\z/i) {
        $self->MODE($user, $nick, $host, $params);
    }
#    elsif ($command =~ /\ATOPIC\z/i) {
#        $self->TOPIC($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ANAMES\z/i) {
#        $self->NAMES($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ALIST\z/i) {
#        $self->LIST($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AINVITE\z/i) {
#        $self->INVITE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AKICK\z/i) {
#        $self->KICK($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AVERSION\z/i) {
#        $self->VERSION($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ASTATS\z/i) {
#        $self->STATS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ALINKS\z/i) {
#        $self->LINKS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ATIME\z/i) {
#        $self->TIME($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ACONNECT\z/i) {
#        $self->CONNECT($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ATRACE\z/i) {
#        $self->TRACE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AADMIN\z/i) {
#        $self->ADMIN($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AINFO\z/i) {
#        $self->INFO($user, $nick, $host, $params);
#    }
    elsif ($command =~ /\APRIVMSG\z/i) {
#        $self->PRIVMSG($user, $nick, $host, $params);
        if ($CONN{$client}->{registered}) {
            $self->broadcast(":" . $CONN{$client}->{nick} . "!" . $CONN{$client}->{user} . "\@" . $CONN{$client}->{host} . " PRIVMSG $params");
#print STDERR ":" . $CONN{$client}->{nick} . "!" . $CONN{$client}->{user} . "\@" . $CONN{$client}->{host} . " PRIVMSG $params\n";
        }
    }
#    elsif ($command =~ /\ANOTICE\z/i) {
#        $self->NOTICE($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AWHO\z/i) {
#        $self->WHO($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AWHOIS\z/i) {
#        $self->WHOIS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AWHOWAS\z/i) {
#        $self->WHOWAS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AKILL\z/i) {
#        $self->KILL($user, $nick, $host, $params);
#    }
    elsif ($command =~ /\APING\z/i) {
        $self->PING($user, $nick, $host, $params);
    }
    elsif ($command =~ /\APONG\z/i) {
        $self->PONG($user, $nick, $host, $params);
    }
#    elsif ($command =~ /\AERROR\z/i) {
#        $self->ERROR($user, $nick, $host, $params);
#    }
    # OPTIONALS
#    elsif ($command =~ /\AAWAY\z/i) {
#        $self->AWAY($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AREHASH\z/i) {
#        $self->REHASH($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ARESTART\z/i) {
#        $self->RESTART($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\ASUMMON\z/i) {
#        $self->SUMMON($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AUSERS\z/i) {
#        $self->USERS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AWALLOPS\z/i) {
#        $self->WALLOPS($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AUSERHOST\z/i) {
#        $self->USERHOST($user, $nick, $host, $params);
#    }
#    elsif ($command =~ /\AISON\z/i) {
#        $self->ISON($user, $nick, $host, $params);
#    }
#    else {
#    # nick!user@host
#        if ($CONN{$client}->{registered}) {
#            $self->broadcast(":$nick!$user\@$host PRIVMSG #CHAN :$line");
#        }
#    }
}


sub split_messageparts {
    my ($self, $raw) = @_;
    my $client = $self->{server}->{client};
    my $prefix;
    my ($user, $nick, $host, $command, $params);
    my $dummy;

    (defined $raw && $raw) or return undef;
    $raw =~ s/[^\x20-\x7E\r\n\t]//g;
    $raw =~ s/\A[\s\t]+//;
    if ($raw =~ /\A:/) {
        ($prefix, $command, $params) = split (/[\s\t]+/, $raw, 3);
        if (defined $prefix && $prefix) {
            ($nick, $dummy) = split (/[\!]+/, $prefix, 2);
            if (defined $dummy && $dummy) {
                ($user, $host) = split (/[\@]+/, $dummy, 2);
            }
        }
    }
    elsif ($raw =~ /\A(PASS|NICK|USER|SERVER|OPER|QUIT|SQUIT|JOIN|PART|MODE|TOPIC|NAMES|LIST|INVITE|KICK|VERSION|STATS|LINKS|TIME|CONNECT|TRACE|ADMIN|INFO|PRIVMSG|NOTICE|WHO|WHOIS|WHOWAS|KILL|PING|PONG|ERROR|AWAY|REHASH|RESTART|SUMMON|USERS|WALLOPS|USERHOST|ISON)[\s\t]+.*\z/i) {
        ($command, $params) = split (/[\s\t]+/, $raw, 2);
    }
    if (! defined $user || ! $user) {
        if (defined $CONN{$client}->{user}) {
            $user = $CONN{$client}->{user};
        }
        else {
            $user = "";
        }
    }
    if (! defined $nick || ! $nick) {
        if (defined $CONN{$client}->{nick}) {
            $nick = $CONN{$client}->{nick};
        }
        else {
            $nick = "";
        }
    }
    if (! defined $host || ! $host) {
        if (defined $CONN{$client}->{host}) {
            $host = $CONN{$client}->{host};
        }
        else {
            $host = "";
        }
    }
#print STDERR "raw: $raw\n";
#print STDERR "user: $user, nick: $nick, host: $host, command: $command, params: $params\n";
    return ($user, $nick, $host, $command, $params);
}


sub PASS {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! defined $params || ! $params) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PASS :Not enough parameters");
        }
        else {
            $self->send_(":$self->{hostname} 461 unknown PASS :Not enough parameters");
        }
        return;
    }
    if ($CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 462 $CONN{$client}->{nick} :You may not reregister");
        return;
    }
    $CONN{$client}->{pass} = $params;
}


sub NICK {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};
    my ($oldnick, $newnick, $hopcount);

    if (! defined $params || ! $params) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 431 $CONN{$client}->{nick} :No nickname given");
        }
        else {
            $self->send_(":$self->{hostname} 431 unknown :No nickname given");
        }
        return;
    }
    $params =~ s/[\s\t]+\z//;
    ($newnick, $hopcount) = split (/[\s\t]+/, $params, 2);
    if (defined $NICK{$newnick}) {
        if ($CONN{$client}->{registered}) {
            $self->send_(":$self->{hostname} 433 $CONN{$client}->{nick} :Nickname is already in use");
        }
        else {
            $self->send_(":$self->{hostname} 436 unknown :Nickname collision KILL");
        }
        return;
    }
    $NICK{$newnick} = 1;

    if ($CONN{$client}->{registered}) {
        $oldnick = $CONN{$client}->{nick};
        delete $NICK{$oldnick};
    }
    $CONN{$client}->{nick} = $newnick;
    (defined $hopcount && $hopcount) and $CONN{$client}->{hopcount} = $hopcount;
    if (! $CONN{$client}->{registered}) {
        if ($CONN{$client}->{nick} && $CONN{$client}->{user}) {
            $self->register;
        }
        $self->send_("PING :$self->{hostname}");
    }
    else {
        $self->send_(":$oldnick!$CONN{$client}->{user}\@$CONN{$client}->{host} NICK :$newnick");
        $self->broadcast(":$oldnick!$CONN{$client}->{user}\@$CONN{$client}->{host} NICK :$newnick");
#        $self->broadcast("NOTICE $self->{hostname} #CHAN :$oldnick is now known as $newnick");
    }
}


sub USER {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};
    my ($realname, $server);

    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 unknown USER :Not enough parameters");
        return;
    }
    ($user, $host, $server, $realname) = split(/[\s\t]+/, $params, 4);
    if (! defined $realname || ! $realname) {
        $self->send_(":$self->{hostname} 461 unknown USER :Not enough parameters");
        return;
    }
    if ($CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 462 $CONN{$client}->{nick} :You may not reregister");
        return;
    }
    $realname =~ s/\A://;
    $CONN{$client}->{user} = $user;
    $CONN{$client}->{realname} = $realname;
    if ($CONN{$client}->{nick} && $CONN{$client}->{user}) {
        $self->register;
    }
}


sub QUIT {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if ($CONN{$client}->{registered}) {
        $self->broadcast("NOTICE $self->{hostname} :User Disconnected: $CONN{$client}->{user}");
    }
    $self->_close;
}


sub PONG {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PONG :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PONG :Not enough parameters");
        return;
    }
    $CONN{$client}->{last_pong} = INetSim::FakeTime::get_faketime();
}


sub PING {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PING :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PING :Not enough parameters");
        return;
    }
    $params =~ s/\A://;
    $self->send_("PONG $params");
}


sub JOIN {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * JOIN :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} JOIN :Not enough parameters");
        return;
    }
#    $self->broadcast("NOTICE $self->{hostname} :User has joined: $CONN{$client}->{user}");
    $self->broadcast(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} JOIN :$params");
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} JOIN :$params");
    $params =~ s/\A#//;
    $CONN{$client}->{channels} .= "$params,";
}


sub PART {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * PART :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} PART :Not enough parameters");
        return;
    }
#    $self->broadcast("NOTICE $self->{hostname} #CHAN :User has left: $CONN{$client}->{user}");
    $self->broadcast(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} PART :$params");
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} PART :$params");
}


sub MODE {
    my ($self, $user, $nick, $host, $params) = @_;
    my $client = $self->{server}->{client};

    if (! $CONN{$client}->{registered}) {
        $self->send_(":$self->{hostname} 451 unknown * MODE :You have not registered");
        return;
    }
    if (! defined $params || ! $params) {
        $self->send_(":$self->{hostname} 461 $CONN{$client}->{nick} MODE :Not enough parameters");
        return;
    }
    $self->send_(":$CONN{$client}->{nick}!$CONN{$client}->{user}\@$CONN{$client}->{host} MODE :$params");
}


sub register {
    my ($self, $sock, $msg) = @_;
    my $client = $self->{server}->{client};

    $CONN{$client}->{registered} = 1;
    # the server sends replies 001 to 004 to a user upon successful registration
    $self->send_(":$self->{hostname} 001 $CONN{$client}->{nick} :Welcome to the Internet Relay Network $CONN{$client}->{nick}");
    $self->send_(":$self->{hostname} 002 $CONN{$client}->{nick} :Your host is $self->{hostname}, running $self->{version}");
    $self->send_(":$self->{hostname} 003 $CONN{$client}->{nick} :This server was created Oct 04 2009 at 02:47:07");
    $self->send_(":$self->{hostname} 004 $CONN{$client}->{nick} :$self->{hostname} $self->{version}");
    # tell the others about the new client
    $self->broadcast("NOTICE $self->{hostname} :User Connected: $CONN{$client}->{user}");
}


sub broadcast {
    my ($self, $msg) = @_;
    my $sclient = $self->{server}->{client};
    my $select = $self->{server}->{select};

    (defined $msg && $msg) or return;
    my @can_write = $select->can_write(0.01);
    foreach my $receiver (@can_write) {
        next if ($receiver == $sclient);
        next if (! $CONN{$receiver}->{registered});
        next if (! $self->{server}->{select}->exists($receiver));
        $self->send_("$msg", $receiver);
    }
}



sub slog_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    INetSim::Log::SubLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
}



sub dlog_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    INetSim::Log::DebugLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
}



sub send_ {
    my ($self, $msg, $sock) = @_;
    (defined $sock && $sock) or $sock = $self->{server}->{client};

    (defined $msg) or return;
    $msg =~ s/[\r\n]*//;
    print $sock "$msg\r\n";
    $self->slog_("send: $msg", $sock);
    $CONN{$sock}->{last_send} = INetSim::FakeTime::get_faketime();
}



sub new {
  my $class = shift || die "Missing class";
  my $args  = @_ == 1 ? shift : {@_};
  my $self  = bless {server => { %$args }}, $class;
  return $self;
}



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = INetSim::Config::getConfigParameter("Default_BindAddress");
    $self->{server}->{port}   = INetSim::Config::getConfigParameter("IRC_BindPort");
    $self->{server}->{proto}  = 'tcp';
    $self->{server}->{type}  = SOCK_STREAM;
    $self->{server}->{user}   = INetSim::Config::getConfigParameter("Default_RunAsUser");
    $self->{server}->{group}  = INetSim::Config::getConfigParameter("Default_RunAsGroup");

    $self->{servicename} = INetSim::Config::getConfigParameter("IRC_ServiceName");
    $self->{maxchilds} = INetSim::Config::getConfigParameter("Default_MaxChilds");
    $self->{timeout} = INetSim::Config::getConfigParameter("Default_TimeOut");

    $self->{hostname} = INetSim::Config::getConfigParameter("IRC_FQDN_Hostname");
    $self->{version} = INetSim::Config::getConfigParameter("IRC_Version");
}



sub pre_loop_hook {
    my $self = shift;

    $0 = 'inetsim_' . $self->{servicename};
    INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}



sub pre_server_close_hook {
    my $self = shift;

    INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}



sub fatal_hook {
    my ($self, $msg) = @_;

    if (defined $msg) {
        $msg =~ s/[\r\n]*//;
        INetSim::Log::MainLog("failed! $!", $self->{servicename});
    }
    else {
        INetSim::Log::MainLog("failed!", $self->{servicename});
    }
    exit 1;
}



sub server_close {
    my $self = shift;

    $self->{server}->{socket}->close();
    exit 0;
}



sub bind {
    my $self = shift;

    # evil untaint
    $self->{server}->{host} =~ /(.*)/;
    $self->{server}->{host} = $1;

    # bind to socket
    $self->{server}->{socket} = new IO::Socket::INET( Listen     => 1,
                                                      LocalAddr  => $self->{server}->{host},
                                                      LocalPort  => $self->{server}->{port},
                                                      Proto      => $self->{server}->{proto},
                                                      Type       => $self->{server}->{type},
                                                      ReuseAddr  => 1
                                                    );
    (defined $self->{server}->{socket}) or $self->fatal_hook("$!");

    # add socket to select
    $self->{server}->{select} = new IO::Select($self->{server}->{socket});
    (defined $self->{server}->{select}) or $self->fatal_hook("$!");

    # drop root privileges
    my $uid = getpwnam($self->{server}->{user});
    my $gid = getgrnam($self->{server}->{group});
    # group
    POSIX::setgid($gid);
    my $newgid = POSIX::getgid();
    if ($newgid != $gid) {
        INetSim::Log::MainLog("failed! (Cannot switch group)", $self->{servicename});
        $self->server_close;
    }
    # user
    POSIX::setuid($uid);
    if ($< != $uid || $> != $uid) {
        $< = $> = $uid; # try again - reportedly needed by some Perl 5.8.0 Linux systems
        if ($< != $uid) {
            INetSim::Log::MainLog("failed! (Cannot switch user)", $self->{servicename});
            $self->server_close;
        }
    }

    # ignore SIG_INT, SIG_PIPE and SIG_QUIT
    $SIG{'INT'} = $SIG{'PIPE'} = $SIG{'QUIT'} = 'IGNORE';
    # only "listen" for SIG_TERM from parent process
    $SIG{'TERM'} = sub { $self->pre_server_close_hook; $self->server_close; };
}



sub run {
    my $self = ref($_[0]) ? shift() : shift->new;

    # configure this service
    $self->configure_hook;
    # open the socket and drop privilegies (set user/group)
    $self->bind;
    # just for compatibility with net::server
    $self->pre_loop_hook;
    # standard loop for: _accept->process_request->_close
    $self->loop;
    # just for compatibility with net::server
    $self->pre_server_close_hook;
    # shutdown socket and exit
    $self->server_close;
}


sub _close {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $client->peerhost;
    my $rport = $client->peerport;

    INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    if ($self->{server}->{select}->exists($client)) {
        $self->{server}->{select}->remove($client);
    }
    $client->close;
    delete $CONN{$client};
}





sub error_exit {
    my ($self, $sock, $msg) = @_;
    my $rhost = $sock->peerhost;
    my $rport = $sock->peerport;

    if (! defined $msg) {
        $msg = "Unknown error";
    }
    INetSim::Log::MainLog("$msg. Closing connection.", $self->{servicename});
    INetSim::Log::SubLog("[$rhost:$rport] error: $msg. Closing connection.", $self->{servicename}, $$);
    INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    exit 1;
}


1;
#
