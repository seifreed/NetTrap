# -*- perl -*-
#
# INetSim::SMTP - A fake SMTP server
#
# RFC 821/2821 - SIMPLE MAIL TRANSFER PROTOCOL (SMTP)
#
# (c)2007-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::SMTP;

use strict;
use warnings;
use base qw(INetSim::GenericServer);
use MIME::Base64;
use Digest::SHA;

my $SSL = 0;
eval { require IO::Socket::SSL; };
if (! $@) { $SSL = 1; };


# http://www.iana.org/assignments/mail-parameters
my %EXT_AVAIL = ( "HELP"                =>        1,        # RFC 821, 2821
                  "SEND"                =>        1,        # RFC 821, 2821
                  "SAML"                =>        1,        # RFC 821, 2821
                  "SOML"                =>        1,        # RFC 821, 2821
                  "VRFY"                =>        1,        # RFC 821, 2821
                  "EXPN"                =>        1,        # RFC 821, 2821
                  "TURN"                =>        1,        # RFC 821, 2821
                  "DSN"                 =>        1,        # RFC 3461
                  "ETRN"                =>        1,        # RFC 1985
                  "VERP"                =>        1,        # http://tools.ietf.org/html/draft-varshavchik-verp-smtpext-00
                  "MTRK"                =>        1,        # RFC 3885
                  "SIZE"                =>        2,        # RFC 1870
                  "AUTH"                =>        2,        # RFC 4954
                  "8BITMIME"            =>        1,        # RFC 1652
                  "DELIVERBY"           =>        2,        # RFC 2852
                  "SUBMITTER"           =>        1,        # RFC 4405
                  "NO-SOLICITING"       =>        2,        # RFC 3865
                  "FUTURERELEASE"       =>        2,        # RFC 4865
                  "ENHANCEDSTATUSCODES" =>        1,        # RFC 2034
                  "ATRN"                =>        1,        # RFC 2645
                  "VERB"                =>        0,        # no RFC available (sendmail specific ?)
                  "ONEX"                =>        0,        # no RFC available (sendmail specific ?)
                  "CHUNKING"            =>        1,        # RFC 3030
                  "BINARYMIME"          =>        1,        # RFC 3030
                  "CHECKPOINT"          =>        1,        # RFC 1845
                  "PIPELINING"          =>        0,        # RFC 2920
                  "STARTTLS"            =>        1,        # RFC 3207 (2487)
                  "UTF8SMTP"            =>        0         # RFC 5336
);
# status: 24 of 28  :-)

my %MAIL_AVAIL = ( "DSN"                =>        "RET,ENVID",
                   "VERP"               =>        "VERP",
                   "MTRK"               =>        "MTRK,ENVID",
                   "SIZE"               =>        "SIZE",
                   "8BITMIME"           =>        "BODY",
                   "DELIVERBY"          =>        "BY",
                   "SUBMITTER"          =>        "SUBMITTER",
                   "NO-SOLICITING"      =>        "SOLICIT",
                   "FUTURERELEASE"      =>        "HOLDFOR,HOLDUNTIL",
                   "BINARYMIME"         =>        "BODY",
                   "CHECKPOINT"         =>        "TRANSID",
                   "UTF8SMTP"           =>        "ALT-ADDRESS",
                   "AUTH"               =>        "AUTH"
);
my %RCPT_AVAIL = ( "DSN"                =>        "NOTIFY,ORCPT",
                   "MTRK"               =>        "ORCPT",
                   "UTF8SMTP"           =>        "ALT-ADDRESS"
);
my %VRFY_AVAIL = ( "UTF8SMTP"           =>        "UTF8REPLY"
);
my %EXPN_AVAIL = ( "UTF8SMTP"           =>        "UTF8REPLY"
);

my %SMTP_EXT = ();
my @RECIPIENTS = ();
my %MAIL_PARAM = ();
my %RCPT_PARAM = ();
my %VRFY_PARAM = ();
my %EXPN_PARAM = ();

my %status;



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{proto}  = 'tcp';                                                      # TCP protocol
    $self->{server}->{user}   = INetSim::Config::getConfigParameter("Default_RunAsUser");   # user to run as
    $self->{server}->{user}   =~ /\A(.*)\z/; # evil untaint!
    $self->{server}->{user}   = $1;
    $self->{server}->{group}  = INetSim::Config::getConfigParameter("Default_RunAsGroup");  # group to run as
    $self->{server}->{group}  =~ /\A(.*)\z/; # evil untaint!
    $self->{server}->{group}  = $1;
    $self->{server}->{setsid} = 0;                                                          # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                                                # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                                       # do not log anything
    # cert directory
    $self->{cert_dir} = INetSim::Config::getConfigParameter("CertDir");

    if (defined $self->{server}->{'SSL'} && $self->{server}->{'SSL'}) {
        $self->{servicename} = INetSim::Config::getConfigParameter("SMTPS_ServiceName");
        if (! $SSL) {
            INetSim::Log::MainLog("failed! Library IO::Socket::SSL not installed", $self->{servicename});
            exit 1;
        }
        $self->{ssl_key} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("SMTPS_KeyFileName") ? INetSim::Config::getConfigParameter("SMTPS_KeyFileName") : INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("SMTPS_CrtFileName") ? INetSim::Config::getConfigParameter("SMTPS_CrtFileName") : INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined INetSim::Config::getConfigParameter("SMTPS_DHFileName") ? INetSim::Config::getConfigParameter("SMTPS_DHFileName") : INetSim::Config::getConfigParameter("Default_DHFileName"));
        if (! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
            INetSim::Log::MainLog("failed! Unable to read SSL certificate files", $self->{servicename});
            exit 1;
        }
        $self->{ssl_enabled} = 1;
        $self->{server}->{port}   = INetSim::Config::getConfigParameter("SMTPS_BindPort");  # bind to port
        # ESMTP
        $self->{ESMTP} = INetSim::Config::getConfigParameter("SMTPS_Extended_SMTP");
        # reversible authentication mechanisms only
        $self->{auth_reversible_only} = INetSim::Config::getConfigParameter("SMTPS_AuthReversibleOnly");
        # force authentication
        $self->{auth_required} = INetSim::Config::getConfigParameter("SMTPS_AuthRequired");
        # mbox file
        $self->{mboxFile} = INetSim::Config::getConfigParameter("SMTPS_MBOXFileName");
        $self->{mboxFile} =~ /\A(.*)\z/; # evil untaint!
        $self->{mboxFile} = $1;
        # smtp banner
        $self->{banner} = INetSim::Config::getConfigParameter("SMTPS_Banner");
        # fqdn hostname
        $self->{fqdn_hostname} = INetSim::Config::getConfigParameter("SMTPS_FQDN_Hostname");
        # helo/ehlo required
        $self->{helo_required} = INetSim::Config::getConfigParameter("SMTPS_HELO_required");
    }
    else {
        $self->{servicename} = INetSim::Config::getConfigParameter("SMTP_ServiceName");
        $self->{ssl_key} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("SMTP_KeyFileName") ? INetSim::Config::getConfigParameter("SMTP_KeyFileName") : INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("SMTP_CrtFileName") ? INetSim::Config::getConfigParameter("SMTP_CrtFileName") : INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined INetSim::Config::getConfigParameter("SMTP_DHFileName") ? INetSim::Config::getConfigParameter("SMTP_DHFileName") : INetSim::Config::getConfigParameter("Default_DHFileName"));
        $self->{ssl_enabled} = 0;
        $self->{server}->{port}   = INetSim::Config::getConfigParameter("SMTP_BindPort");  # bind to port
        # ESMTP
        $self->{ESMTP} = INetSim::Config::getConfigParameter("SMTP_Extended_SMTP");
        # reversible authentication mechanisms only
        $self->{auth_reversible_only} = INetSim::Config::getConfigParameter("SMTP_AuthReversibleOnly");
        # force authentication
        $self->{auth_required} = INetSim::Config::getConfigParameter("SMTP_AuthRequired");
        # mbox file
        $self->{mboxFile} = INetSim::Config::getConfigParameter("SMTP_MBOXFileName");
        $self->{mboxFile} =~ /\A(.*)\z/; # evil untaint!
        $self->{mboxFile} = $1;
        # smtp banner
        $self->{banner} = INetSim::Config::getConfigParameter("SMTP_Banner");
        # fqdn hostname
        $self->{fqdn_hostname} = INetSim::Config::getConfigParameter("SMTP_FQDN_Hostname");
        # helo/ehlo required
        $self->{helo_required} = INetSim::Config::getConfigParameter("SMTP_HELO_required");
    }

    # warn about missing dh file and disable
    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $self->{ssl_dh} = $self->{cert_dir} . $self->{ssl_dh};
        if (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh}) {
            INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
            $self->{ssl_dh} = undef;
        }
    }

    my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks, $grpname) = undef;

    # timeout
    $self->{timeout} = INetSim::Config::getConfigParameter("Default_TimeOut");
    # max childs
    $self->{maxchilds} = INetSim::Config::getConfigParameter("Default_MaxChilds");

    if (! open (DAT, ">> $self->{mboxFile}")) {
        INetSim::Log::MainLog("Warning: Unable to open SMTP mbox file '$self->{mboxFile}': $!", $self->{servicename});
    }
    else {
        close DAT;
        chmod 0660, $self->{mboxFile};
        $gid = getgrnam($self->{server}->{group});
        if (! defined $gid) {
            INetSim::Log::MainLog("Warning: Unable to get GID for group '$self->{server}->{group}'", $self->{servicename});
        }
        chown -1, $gid, $self->{mboxFile};
        ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{mboxFile};
        $grpname = getgrgid $gid;
        # check group owner
        if ($grpname ne $self->{server}->{group}) {
            INetSim::Log::MainLog("Warning: Group owner of SMTP mbox file '$self->{mboxFile}' is not '$self->{server}->{group}' but '$grpname'", $self->{servicename});
        }
        # check for group r/w permissions
        if ((($mode & 0060) >> 3) != 6) {
            INetSim::Log::MainLog("Warning: No group r/w permissions on SMTP mbox file '$self->{mboxFile}'", $self->{servicename});
        }
    }

    # register configured (and available) service extensions and guess the mail transmission type
    $self->register_extensions;

    # just a gimmick: simple replacing the word xSMTPx in the banner string with the mail transmission type ;-)
    if ($self->{banner} =~ /\A(|.*\s)xSMTPx(|\s.*)\z/) {
        $self->{banner} =~ s/xSMTPx/$self->{mailTransmissionType}/;
    }
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
    my $self = shift;

    INetSim::Log::MainLog("failed!", $self->{servicename});
    exit 1;
}



sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};

    # status, counters ...
    $status{success} = 0;
    $status{auth_type} = "";
    $status{credentials} = "";
    $status{count_mails} = 0;
    $status{count_bytes} = 0;
    $status{count_recipients} = 0;
    $status{tls_used} = 0;
    $status{tls_cipher} = "";
    # flags
    $self->{EHLO} = 0;
    $self->{auth_given} = 0;
    $self->{helo_given} = 0;
    $self->{sender_given} = 0;
    $self->{recipient_given} = 0;
    $self->{transaction} = 0;
    $self->{bdat_last} = 0;
    $self->{bdat_incomplete} = 0;
    $self->{using_tls} = 0;
    # other
    @RECIPIENTS = ();
    $self->{envelope_sender} = undef;
    $self->{envelope_recipient} = undef;
    $self->{transaction_type} = "";
    $self->{body_mime} = "";
    $self->{bdat_content} = "";
    $self->{size} = 0;
    $self->{transid} = "";

    if ($self->{ssl_enabled} && ! $self->upgrade_to_ssl()) {
        $self->slog_("connect");
        $self->slog_("info: Error setting up SSL:  $self->{last_ssl_error}");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        return;
    }
    if ($self->{server}->{numchilds} >= $self->{maxchilds}) {
        $self->slog_("connect");
        $self->send_(421, "Maximum number of connections ($self->{maxchilds}) exceeded.", "4.3.2");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        return;
    }
    my $line = "";
    eval {
        local $SIG{'ALRM'} = sub { die "TIMEOUT" };
        alarm($self->{timeout});
        $self->slog_("connect");
        ### Server Greeting
        $self->send_(220, "$self->{fqdn_hostname} $self->{banner}");
        # wait for command
        while ($line = <$client>) {
            chomp($line);
            $line =~ s/\r\z//g;
            $line =~ s/[\r\n]+//g;
            $line =~ s/[\t]/\ /g;
            alarm($self->{timeout});
            $self->slog_("recv: $line");
            ### HELO
            if ($line =~ /\AHELO(|([\s]+)(.*))\z/i) {
                $self->HELO($3);
            }
            ### EHLO
            elsif ($self->{ESMTP} && $line =~ /\AEHLO(|([\s]+)(.*))\z/i) {
                $self->EHLO($3);
            }
            ### MAIL or SEND or SOML or SAML
            elsif ($line =~ /\A(MAIL|SEND|SOML|SAML)(|([\s]+)(.*))\z/i) {
                $self->MAIL(uc($1), $4);
            }
            ### RCPT
            elsif ($line =~ /\ARCPT(|([\s]+)(.*))\z/i) {
                $self->RCPT($3);
            }
            ### DATA
            elsif ($line =~ /\ADATA(|([\s]+)(.*))\z/i) {
                $self->DATA($3);
            }
            ### RSET
            elsif ($line =~ /\ARSET(|([\s]+)(.*))\z/i) {
                $self->RSET($3);
            }
            ### NOOP
            elsif ($line =~ /\ANOOP(|([\s]+)(.*))\z/i) {
                $self->NOOP($3);
            }
            ### QUIT
            elsif ($line =~ /\AQUIT(|([\s]+)(.*))\z/i) {
                $self->QUIT($3);
            }
            ### VRFY
            elsif ($line =~ /\AVRFY(|([\s]+)(.*))\z/i) {
                $self->VRFY($3);
            }
            ### EXPN
            elsif (defined $SMTP_EXT{EXPN} && $line =~ /\AEXPN(|([\s]+)(.*))\z/i) {
                $self->EXPN($3);
            }
            ### HELP
            elsif (defined $SMTP_EXT{HELP} && $line =~ /\AHELP(|([\s]+)(.*))\z/i) {
                $self->HELP($3);
            }
            ### TURN
            elsif (defined $SMTP_EXT{TURN} && $line =~ /\ATURN(|([\s]+)(.*))\z/i) {
                $self->TURN("TURN", $3);
            }
            ### ATRN
            elsif ($self->{ESMTP} && defined $SMTP_EXT{ATRN} && $line =~ /\AATRN(|([\s]+)(.*))\z/i) {
                $self->TURN("ATRN", $3);
            }
            ### ETRN
            elsif ($self->{ESMTP} && defined $SMTP_EXT{ETRN} && $line =~ /\AETRN(|([\s]+)(.*))\z/i) {
                    $self->ETRN($3);
            }
            ### AUTH
            elsif ($self->{ESMTP} && defined $SMTP_EXT{AUTH} && $line =~ /\AAUTH(|([\s]+)(.*))\z/i) {
                $self->AUTH($3);
            }
            ### BDAT
            elsif ($self->{ESMTP} && defined $SMTP_EXT{CHUNKING} && $line =~ /\ABDAT(|([\s]+)(.*))\z/i) {
                $self->BDAT($3);
            }
            ### STARTTLS
            elsif ($self->{ESMTP} && defined $SMTP_EXT{STARTTLS} && $line =~ /\ASTARTTLS(|([\s]+)(.*))\z/i) {
                $self->STARTTLS($3);
            }
            ### unknown
            else {
                $self->send_(500, "Error: unknown command", "5.5.1");
            }
            last if ($self->{close_connection});
            alarm($self->{timeout});
        }
    };
    alarm(0);
    if ($@ =~ /TIMEOUT/) {
        $self->send_(421, "Error: timeout exceeded", "4.4.2");
        $self->slog_("disconnect (timeout)");
    }
    else {
        if (defined ($self->{timed_out}) && $self->{timed_out}) {        # only needed for turn/atrn
            $self->slog_("disconnect (timeout)");
        }
        else {
            $self->slog_("disconnect");
        }
    }
    # connection lost ? write incomplete, checkpointed message
    if ($self->{transid} && $self->{data_incomplete} && $self->{data_content}) {
        $self->write_message($self->{data_content});
    }
    $status{count_recipients} = @RECIPIENTS;        # sum of all recipients !
    $self->slog_("stat: $status{success}" . (($status{success} == 1) ? " mails=$status{count_mails} recips=$status{count_recipients} auth=$status{auth_type} creds=$status{credentials} bytes=$status{count_bytes} tls=$status{tls_used} cipher=$status{tls_cipher}" : ""));
}



sub slog_ {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (defined ($msg)) {
        $msg =~ s/[\r\n]*//;
        INetSim::Log::SubLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
    }
}



sub send_ {
    my ($self, $code, $msg, $ecode) = @_;
    my $client = $self->{server}->{client};

    if (defined ($code) && $code ne "" && defined ($msg) && $msg ne "") {
        alarm($self->{timeout});
        $msg =~ s/[\r\n]*//;
        # workaround for non-multiline replies
        if ($code =~ /\d\z/) {
            $code .= " ";
        }
        if ($self->{ESMTP} && defined ($SMTP_EXT{ENHANCEDSTATUSCODES}) && defined ($ecode) && $ecode ne "" && $ecode =~ /\A(2|4|5)/ && substr($code, 0, 1) eq substr($ecode, 0, 1)) {
            print $client "$code$ecode $msg\r\n";
            $self->slog_("send: $code$ecode $msg");
        }
        elsif ($code =~ /\A000/) {
            print $client "$msg\r\n";
            $self->slog_("send: $msg");
        }
        else {
            print $client "$code$msg\r\n";
            $self->slog_("send: $code$msg");
        }
        alarm($self->{timeout});
    }
}



sub recv_ {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $line;

    alarm($self->{timeout});
    $line = <$client>;
    alarm($self->{timeout});
    if (! defined ($line)) {
        $line = "";
    }
    chomp($line);
    $line =~ s/\r\z//g;
    $line =~ s/[\r\n]+//g;
    $self->slog_("recv: $line");
    return $line;
}



sub HELO {
    my ($self, $args) = @_;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("HELO");
        return;
    }

    # (re)set variables
    $self->{EHLO} = 0;
    $self->{helo_given} = 1;
    $self->{sender_given} = 0;
    $self->{recipient_given} = 0;
    $self->{envelope_sender} = undef;
    $self->{envelope_recipient} = undef;
    $self->{transaction} = 0;
    $self->{transaction_type} = "";
    $self->{bdat_last} = 0;
    $self->{bdat_content} = "";
    $self->{bdat_incomplete} = 0;
    $self->{body_mime} = "";
    # output
    $self->send_(250, $self->{fqdn_hostname});
}



sub EHLO {
    my ($self, $args) = @_;
    my @out = ();
    my $last;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("EHLO");
        return;
    }

    # (re)set variables
    $self->{EHLO} = 1;
    $self->{helo_given} = 1;
    $self->{sender_given} = 0;
    $self->{recipient_given} = 0;
    $self->{envelope_sender} = undef;
    $self->{envelope_recipient} = undef;
    $self->{transaction} = 0;
    $self->{transaction_type} = "";
    $self->{bdat_last} = 0;
    $self->{bdat_content} = "";
    $self->{bdat_incomplete} = 0;
    $self->{body_mime} = "";
    # do multiline output
    push (@out, $self->{fqdn_hostname});
    foreach (keys %SMTP_EXT) {
        if ($SMTP_EXT{$_} ne "") {
            push (@out, "$_ $SMTP_EXT{$_}");
        }
        else {
            push (@out, "$_");
        }
    }
    $last = pop(@out);
    foreach (@out) {
        $self->send_("250-", "$_");
    }
    $self->send_(250, $last);
}



sub MAIL {
    my ($self, $cmd, $args) = @_;

    if ($cmd ne "MAIL" && ! defined $SMTP_EXT{$cmd}) {
        $self->send_(500, "Error: unknown command", "5.5.1");
        return;
    }

    return if $self->helo_required;
    return if $self->auth_required;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/ || $args !~ /\AFROM:/i) {
        $self->syntax($cmd);
        return;
    }
    $args =~ s/\AFROM:([\s\t]+)?//i;
    my $sender = $self->get_parameters("MAIL", $args);
    # address invalid -> syntax error
    if (! defined $sender) {
        $self->syntax($cmd);
        return;
    }
    # unknown option/parameter
    if ($self->{invalid_keyword}) {
        $self->send_(555, "Error: Unsupported option", "5.5.4");
        return;
    }
    # look for body parameter
    if (defined ($MAIL_PARAM{BODY}) && $MAIL_PARAM{BODY} =~ /\ABINARYMIME/i) {
        $self->{body_mime} = "binary";
    }
    elsif (defined ($MAIL_PARAM{BODY}) && $MAIL_PARAM{BODY} =~ /\A7BIT/i) {
        $self->{body_mime} = "7bit";
    }
    elsif (defined ($MAIL_PARAM{BODY}) && $MAIL_PARAM{BODY} =~ /\A8BITMIME/i) {
        $self->{body_mime} = "8bit";
    }
    else {
        $self->{body_mime} = "";
    }
    # look for transaction id parameter
    if (defined ($MAIL_PARAM{TRANSID}) && $MAIL_PARAM{TRANSID} ne "") {
        $self->{transid} = $MAIL_PARAM{TRANSID};
    }
    else {
        $self->{transid} = "";
    }
    # look for size parameter
    if (defined ($MAIL_PARAM{SIZE}) && $MAIL_PARAM{SIZE} =~ /\A([\d]+)/) {
        $self->{size} = $1;
    }
    else {
        $self->{size} = 0;
    }
    if ($sender =~ /\A\<([\s]+)?\>\z/) {
        # substitue '<>' with 'MAILER-DAEMON'
        $sender = "MAILER-DAEMON";
    }
    else {
        # remove '<' and '>'
        $sender =~ s/\<(.*)\>/$1/g;
    }

    if (defined $self->{size} && $self->{size} && $self->{size} > $self->{max_message_size}) {
        $self->send_(552, "Error: Message exceeds maximum size", "5.2.3");
        return;
    }
    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if (! defined $sender || $sender eq "") {
        $self->syntax("MAIL");
        return;
    }
    # body=binarymime not allowed without binarymime extension
    if (! defined $SMTP_EXT{BINARYMIME} && $self->{body_mime} eq "binary") {
        $self->send_(555, "Error: Unsupported option", "5.5.4");
        return;
    }
    $self->{sender_given} = 1;
    $self->{envelope_sender} = $sender;
    $self->{recipient_given} = 0;
    $self->{envelope_recipient} = undef;
    $self->{transaction} = 1;
    # check for transid parameter
    if ($self->{transid}) {
        # searching for checkpoint
        $self->search_checkpoint($self->{transid}, $sender);
        # ok, checkpoint found
        if ($self->{checkpoint_found}) {
            $self->{recipient_given} = 1;
            # send code 355 and the offset
            $self->send_(355, "$self->{transaction_offset} is the transaction offset");
            return;
        }
    }
    $self->send_(250, "Ok", "2.1.0");
}



sub RCPT {
    my ($self, $args) = @_;

    return if $self->helo_required;
    return if $self->auth_required;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/ || $args !~ /\ATO:/i) {
        $self->syntax("RCPT");
        return;
    }
    if (! $self->{sender_given}) {
        $self->send_(503, "Error: need MAIL command", "5.5.1");
        return;
    }
    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    $args =~ s/\ATO:([\s\t]+)?//i;
    my $recipient = $self->get_parameters("RCPT", $args);
    # address invalid -> syntax error
    if (! defined $recipient) {
        $self->syntax("RCPT");
        return;
    }
    # unknown option/parameter
    if ($self->{invalid_keyword}) {
        $self->send_(555, "Error: Unsupported option", "5.5.4");
        return;
    }
    if ($recipient =~ /\A\<([\s]+)?\>\z/) {
        # substitute '<>' with 'POSTMASTER'
        $recipient = "POSTMASTER";
    }
    else {
        # remove '<' and '>'
        $recipient =~ s/\<(.*)\>/$1/g;
    }
    if (! defined $recipient || $recipient eq "") {
        $self->syntax("RCPT");
        return;
    }
    if ($self->{transid} && $self->{checkpoint_found}) {
        $self->{transid} = "";
    }
    $self->{recipient_given} = 1;
    $self->{envelope_recipient} = $recipient if (! defined $self->{envelope_recipient});
    push (@RECIPIENTS, $recipient);
    $self->send_(250, "Ok", "2.1.5");
}



sub DATA {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};
    my $data = "";
    my $bytes = 0;
    my $queueid;
    my $err_size = 0;

    return if $self->helo_required;
    return if $self->auth_required;

    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
        $self->syntax("DATA");
        return;
    }

    if (! $self->{recipient_given}) {
        $self->send_(503, "Error: need RCPT command", "5.5.1");
        return;
    }
    if (! $self->{sender_given}) {
        $self->send_(503, "Error: need MAIL command", "5.5.1");
        return;
    }
    # check for running bdat transaction
    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: Bad sequence of commands", "5.5.1");
        return;
    }
    # check for BINARYMIME flag, because it cannot be used with DATA
    if ($self->{body_mime} eq "binary") {
        $self->send_(503, "Error: Bad sequence of commands", "5.5.1");
        return;
    }
    $self->{transaction_type} = "data";
    $self->{data_content} = "";
    $self->{data_incomplete} = 1;
    if ($self->{transid}) {
        if ($self->{checkpoint_found}) {
            $self->send_(354, "Send previously checkpointed message starting at octet $self->{transaction_offset}");
        }
        else {
            $self->send_(354, "Send checkpointed message, end data with <CR><LF>.<CR><LF>");
        }
    }
    else {
        $self->send_(354, "End data with <CR><LF>.<CR><LF>");
    }
    while (<$client>) {
        alarm($self->{timeout});
        if(/\A\.[\r\n]*\z/) {
            $bytes = length($self->{data_content});
            $status{count_mails}++;
            $status{count_bytes} += $bytes;
            $self->slog_("recv: <(MESSAGE)> ($bytes bytes)");
            $self->slog_("recv: .");
            $self->{data_incomplete} = 0;
            $queueid = $self->write_message($self->{data_content});
            $self->{transaction_type} = "";
            $self->{sender_given} = 0;
            $self->{recipient_given} = 0;
            if ($err_size) {
                $self->send_(452, "Error: Message size limit exceeded", "4.2.3");
                $self->slog_("info: Message truncated");
                return;
            }
            if (defined ($queueid)) {
                $status{success} = 1;
                $self->send_(250, "Ok: queued as $queueid", "2.6.0");
            }
            else {
                $self->send_(451, "Error: local error in processing", "4.3.0");
            }
            return;
        }
        elsif ($err_size || ($self->{max_message_size} && length($self->{data_content}) > $self->{max_message_size})) {
            $err_size = 1;
        }
        else {
            $self->{data_content} .= $_;
        }
        alarm($self->{timeout});
    }
}



sub BDAT {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};
    my $message_size = 0;
    my $chunk_length = 0;
    my $bytes = 0;
    my $received = "";
    my $err_seq = 0;
    my $err_size = 0;
    my $fileName;
    my @message = ();

    return if $self->helo_required;
    return if $self->auth_required;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("BDAT");
        return;
    }
    if (! $self->{recipient_given}) {
        $self->send_(503, "Error: need RCPT command", "5.5.1");
        return;
    }
    if (! $self->{sender_given}) {
        $self->send_(503, "Error: need MAIL command", "5.5.1");
        return;
    }
    if ($self->{transaction_type} eq "data") {
        $self->send_(503, "Error: Bad sequence of commands", "5.5.1");
        return;
    }
    if ($self->{transid}) {
        $self->send_(503, "Error: Bad sequence of commands", "5.5.1");
        return;
    }
    $args =~ s/\A[\s]+//;
    $args =~ s/[\s]+\z//;
    if ($args !~ /\A([\d]+|LAST|[\d]+[\s]+LAST)\z/i) {
        $self->send_(501, "Error: invalid parameter syntax", "5.5.4");
        return;
    }
    # quote from RFC:
    # "Any BDAT command sent after the BDAT LAST is illegal and
    # MUST be replied to with a 503 "Bad sequence of commands" reply code."
    if ($self->{bdat_last}) {
        $err_seq = 1;
    }
    $self->{transaction_type} = "bdat";
    if ($args =~ /\A([\d]+)\z/) {
        # more chunks follow after this chunk
        $chunk_length = $1;
    }
    elsif ($args =~ /\A([\d]+)[\s]+LAST\z/i) {
        # this is the last chunk, size is given
        $self->{bdat_last} = 1;
        $chunk_length = $1;
    }
    elsif ($args =~ /\ALAST\z/i) {
        # this is the last chunk, no size parameter given
        $self->{bdat_last} = 1;
        $chunk_length = 0;
    }
    else {
        $self->send_(501, "Error: invalid parameter syntax", "5.5.4");
        # hmm, could be some kind of DoS -> close connection
        $self->{close_connection} = 1;
    }
    # must receive all data, before return anything
    while ($bytes < $chunk_length) {
        alarm($self->{timeout});
        $received = <$client>;
        alarm($self->{timeout});
        if (! defined ($received)) {
            $received = "";
        }
        $bytes += length($received);
        # if transaction is already completed or content reaches $maxlength, simply discard more data
        if (! $err_seq) {
            if ($bytes < $self->{max_chunk_length}) {
                $self->{bdat_content} .= $received;
            }
            else {
                $err_size = 1;
            }
        }
    }
    $self->slog_("recv: <(CHUNK)> ($bytes bytes)");
    $message_size = length($self->{bdat_content});
    if ($err_seq) {
        $self->send_(503, "Error: Bad sequence of commands", "5.5.1");
    }
    elsif ($err_size) {
        $self->send_(452, "Error: Chunk size limit exceeded", "4.2.3");
        $self->slog_("info: Chunk truncated");
        $self->{bdat_incomplete} = 1;
    }
    else {
        if ($self->{bdat_last}) {
            $self->{body_mime} = "";
            if ($self->write_message($self->{bdat_content})) {
                $status{count_bytes} += $message_size;
                $status{count_mails}++;
                if ($self->{max_message_size} && $message_size > $self->{max_message_size}) {
                    $self->send_(452, "Error: Message size limit exceeded", "4.2.3");
                }
                else {
                    $self->send_(250, "Message OK, $message_size octets received", "2.6.0");
                }
                if ($self->{bdat_incomplete}) {
                    $self->slog_("info: Message incomplete");
                    $self->{bdat_incomplete} = 0;
                }
            }
            else {
                $self->send_(451, "Error: local error in processing", "5.3.0");
            }
        }
        else {
            $self->send_(250, "$bytes octets received", "2.6.0");
        }
    }
}



sub RSET {
    my ($self, $args) = @_;

    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
        $self->syntax("RSET");
        return;
    }

    # reset variables
    $self->{sender_given} = 0;
    $self->{recipient_given} = 0;
    $self->{envelope_sender} = undef;
    $self->{envelope_recipient} = undef;
    $self->{transaction} = 0;
    $self->{transaction_type} = "";
    $self->{bdat_last} = 0;
    $self->{bdat_content} = "";
    $self->{bdat_incomplete} = 0;
    $self->{body_mime} = "";
    # reply
    $self->send_(250, "Ok", "2.0.0");
}



sub NOOP {
    my ($self, $args) = @_;

    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
        $self->syntax("NOOP");
        return;
    }

    # reply
    $self->send_(250, "Ok", "2.0.0");
}



sub QUIT {
    my ($self, $args) = @_;

#    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
#        $self->syntax("QUIT");
#        return;
#    }

    $self->{close_connection} = 1;

    # reply
    $self->send_(221, "closing connection.", "2.0.0");
}



sub VRFY {
    my ($self, $args) = @_;

    if (! defined $SMTP_EXT{VRFY}) {
        if ($self->{ESMTP}) {
            $self->send_(502, "Error: command not implemented", "5.5.1");
        }
        else {
            $self->send_(500, "Error: unknown command", "5.5.1");
        }
        return;
    }

    return if $self->auth_required;

    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("VRFY");
        return;
    }
    my $address = $self->get_parameters("VRFY", $args);
    # address invalid -> syntax error
    if (! defined $address || $address eq "") {
        $self->syntax("VRFY");
        return;
    }
    # unknown option/parameter
    if ($self->{invalid_keyword}) {
        $self->send_(555, "Error: Unsupported option", "5.5.4");
        return;
    }
    if ($address =~ /\<([\x21-\x7E]+)\>\z/ || ($address !~ /[\<\>]/ && $address =~ /\A([\x21-\x7E]+)\z/)) {
        $address = $1;
        $address =~ s/[\<\>]//g;
        $self->send_(252, $address, "2.0.0");
    }
    else {
        $self->send_(501, "Bad address syntax", "5.1.3");
    }
}



sub EXPN {
    my ($self, $args) = @_;

    return if $self->auth_required;

    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("EXPN");
        return;
    }
    my $address = $self->get_parameters("EXPN", $args);
    # address invalid -> syntax error
    if (! defined $address || $address eq "") {
        $self->syntax("EXPN");
        return;
    }
    # unknown option/parameter
    if ($self->{invalid_keyword}) {
        $self->send_(555, "Error: Unsupported option", "5.5.4");
        return;
    }
    if ($address =~ /([^a-zA-Z0-9\-\.\_\+\=\s])/) {
        $self->send_(501, "Error: invalid parameter syntax", "5.5.4");
    }
    elsif ($address =~ /[\s]/) {
        $self->syntax("EXPN");
    }
    else {
        $self->send_("250-", "User foo <foo\@inetsim.org>", "2.0.0");
        $self->send_(250, "User bar <bar\@inetsim.org>", "2.0.0");
    }
}



sub ETRN {
    my ($self, $args) = @_;

    return if $self->helo_required;
    return if $self->auth_required;

    if (! defined $args || ! $args || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("ETRN");
        return;
    }

    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if ($args =~ /([^a-zA-Z0-9\-\.\s])/) {
        $self->send_(501, "Error: invalid parameter syntax", "5.5.4");
    }
    else {
        $self->send_(250, "Queuing started", "2.0.0");
    }
}



sub get_credentials {
    my ($self, $mech, $enc) = @_;
    my ($user, $pass, $other) = "";
    my $dec;

    (defined $mech && $mech) or return 0;
    (defined $enc && $enc) or return 0;
    # decode base64
    $enc =~ s/([^\x2B-\x7A])//g;
    $enc =~ s/([\x2C-\x2E])//g;
    $enc =~ s/([\x3A-\x3C])//g;
    $enc =~ s/([\x3E-\x40])//g;
    $enc =~ s/([\x5B-\x60])//g;
    $dec = b64_dec($enc);
    (defined $dec && $dec) or return 0;
    $dec =~ s/[\r\n]*\z//;
    $dec =~ s/[\s\t]{2,}/\ /g;
    $dec =~ s/\A[\s\t]+//;
    ($dec) or return 0;

    # ANONYMOUS: RFC 4505 [2245]
    if ($mech eq "anonymous") {
        $dec =~ s/[\s\t]+\z//;
        # check maximum length
        (length($dec) <= 1024) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $user = $dec;
        $pass = "";
    }
    # PLAIN: RFC 4616 [2595]
    elsif ($mech eq "plain") {
        # check maximum length
        (length($dec) <= 1024) or return 0;
        ($other, $user, $pass) = split(/\x00/, $dec, 3);
        (defined $user && $user && defined $pass && $pass) or return 0;
        $other = "" if (! defined $other);
        $dec =~ s/[\x00]+/\ /g;
        $dec =~ s/\A\s+//g;
        $other =~ s/\A\s+//;
        $user =~ s/\A\s+//;
        $user =~ s/\s+\z//;
        $pass =~ s/\A\s+//;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $other =~ s/([^\x20-\x7e])/\./g;
        $user =~ s/([^\x20-\x7e])/\./g;
        $pass =~ s/([^\x20-\x7e])/\./g;
    }
    # LOGIN: http://tools.ietf.org/html/draft-murchison-sasl-login-00
    # check the username for login mechanism
    elsif ($mech eq "login_user") {
        $dec =~ s/[\s\t]+\z//;
        # check maximum length
        (length($dec) < 64) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $user = $dec;
    }
    # check the password for login mechanism
    elsif ($mech eq "login_pass") {
        # check maximum length
        (length($dec) <= 1024) or return 0;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        $pass = $dec;
    }
    # CRAM-MD5/SHA1: RFC 2195
    elsif ($mech eq "cram-md5" || $mech eq "cram-sha1") {
        $dec =~ s/\s+\z//;
        # replace non-printable characters with "."
        $dec =~ s/([^\x20-\x7e])/\./g;
        ($user, $pass) = split(/\s+/, $dec, 2);
        (defined $user && $user && defined $pass && $pass) or return 0;
        $user =~ s/\s+\z//;
        $pass =~ s/\A\s+//;
        $pass =~ s/\s+\z//;
        # check maximum length
        (length($user) <= 1024) or return 0;
        # check for valid md5
        if ($mech eq "cram-md5" && $pass !~ /\A[[:xdigit:]]{32}\z/) {
            return 0;
        }
        # check for valid sha1
        if ($mech eq "cram-sha1" && $pass !~ /\A[[:xdigit:]]{40}\z/) {
            return 0;
        }
    }

    return ($dec, $user, $pass, $other);
}



sub AUTH {
    my ($self, $args) = @_;
    my $client = $self->{server}->{client};
    my @methods = split(/[\s\t]+/, $SMTP_EXT{AUTH});
    my ($encoded, $decoded);
    my ($user, $pass, $other, $dummy);

    return if $self->helo_required;

    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if ($self->{auth_given}) {
        $self->send_(503, "Already authenticated", "5.5.1");
        return;
    }
    if ($self->{transaction}) {
        $self->send_(503, "Authentication not allowed in transaction state", "5.5.1");
        return;
    }
    if (! defined $args || $args eq "" || $args =~ /\A[\s\t]+\z/) {
        $self->syntax("AUTH");
        return;
    }

    my ($mechanism, $string, $more) = split(/[\s\t]+/, $args, 3);
    if (defined $more && $more && $more !~ /\A[\s\t]+\z/) {
        $self->syntax("AUTH");
        return;
    }

    if (! defined $mechanism || ! $mechanism) {
        $self->syntax("AUTH");
        return;
    }
    if ($mechanism !~ /\A(ANONYMOUS|PLAIN|LOGIN|CRAM-MD5|CRAM-SHA1)\z/i) {
        $self->send_(504, "Unknown authentication method", "5.7.4");
        return;
    }
    $mechanism = lc($mechanism);
    # test for allowed methods
    my $found = 0;
    foreach (@methods) {
        if ($mechanism eq lc($_)) {
            $found = 1;
            last;
        }
    }
    if (! $found) {
        $self->send_(504, "Unknown authentication method", "5.7.4");
        return;
    }

    ### ANONYMOUS or PLAIN
    if ($mechanism eq "anonymous" || $mechanism eq "plain") {
        if (! defined ($string) || $string eq "") {
            $self->send_(334, "Go on");
            alarm($self->{timeout});
            chomp($string = <$client>);
            alarm($self->{timeout});
            $string =~ s/\r\z//g;
            $string =~ s/[\r\n]+//g;
            # replace non-printable characters with "."
            $string =~ s/([^\x20-\x7e])/\./g;
            $self->slog_("recv: $string");
        }
        if (! defined $string || $string eq "") {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        if ($string =~ /\A\*/) {
            $self->send_(501, "Authentication cancelled", "5.7.0");
            return;
        }
        ($decoded, $user, $pass, $other) = $self->get_credentials($mechanism, $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
        if (! defined $user || $user eq "") {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
    }

    ### LOGIN
    elsif ($mechanism eq "login") {
        if (! defined ($string) || $string eq "") {
            # ask for username
            $self->send_(334, "VXNlcm5hbWU6");
            $self->slog_("info: VXNlcm5hbWU6  -->  Username:");
            alarm($self->{timeout});
            chomp($string = <$client>);
            alarm($self->{timeout});
            $string =~ s/\r\z//g;
            $string =~ s/[\r\n]+//g;
            # replace non-printable characters with "."
            $string =~ s/([^\x20-\x7e])/\./g;
            $self->slog_("recv: $string");
        }
        if (! defined $string || $string eq "") {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        if ($string =~ /\A\*/) {
            $self->send_(501, "Authentication cancelled", "5.7.0");
            return;
        }
        ($decoded, $user, $dummy, $other) = $self->get_credentials("login_user", $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
        # ask for password
        $self->send_(334, "UGFzc3dvcmQ6");
        $self->slog_("info: UGFzc3dvcmQ6  -->  Password:");
        alarm($self->{timeout});
        chomp($string = <$client>);
        alarm($self->{timeout});
        $string =~ s/\r\z//g;
        $string =~ s/[\r\n]+//g;
        # replace non-printable characters with "."
        $string =~ s/([^\x20-\x7e])/\./g;
        $self->slog_("recv: $string");
        if (! defined $string || $string eq "") {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        if ($string =~ /\A\*/) {
            $self->send_(501, "Authentication cancelled", "5.7.0");
            return;
        }
        ($decoded, $dummy, $pass, $other) = $self->get_credentials("login_pass", $string);
        if (! defined $decoded || ! $decoded) {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
    }

    ### CRAM-MD5 or CRAM-SHA1
    elsif ($mechanism eq "cram-md5" || $mechanism eq "cram-sha1") {
        if (defined $string && $string) {
            $self->send_(501, "Error: invalid parameter syntax", "5.5.2");
            return;
        }
        my $greeting = "<$$." . INetSim::FakeTime::get_faketime() . '@' . "$self->{fqdn_hostname}>";
        $encoded = encode_base64($greeting);
        $encoded =~ s/[\r\n]+\z//;
        $self->send_(334, "$encoded");
        $self->slog_("info: $encoded  -->  $greeting");
        alarm($self->{timeout});
        chomp($string = <$client>);
        alarm($self->{timeout});
        ($decoded, $user, $pass, $other) = $self->get_credentials($mechanism, $string);
        $string =~ s/\r\z//g;
        $string =~ s/[\r\n]+//g;
        # replace non-printable characters with "."
        $string =~ s/([^\x20-\x7e])/\./g;
        $self->slog_("recv: $string");
        if (! defined $string || $string eq "") {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        if ($string =~ /\A\*/) {
            $self->send_(501, "Authentication cancelled", "5.7.0");
            return;
        }
        if (! defined $decoded || ! $decoded) {
            $self->send_(535, "Incorrect authentication data", "5.7.8");
            return;
        }
        $self->slog_("info: $string  -->  $decoded");
    }
    else {
        $self->send_(504, "Unknown authentication method", "5.7.4");
        return;
    }

    ### Authentication successful...
    $status{auth_type} = "sasl/$mechanism";
    $status{credentials} = "$user:$pass";
    $self->{auth_given} = 1;

    $self->send_(235, "Authentication successful", "2.7.0");
}



sub TURN {
    my ($self, $command, $args) = @_;
    my $line;
    my ($banner, $ehlo, $helo, $mail, $rcpt, $data, $content, $quit) = 0;

    return if $self->helo_required;
    return if $self->auth_required;

    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
        $self->syntax($command);
        return;
    }

    if ($self->{transaction_type} eq "bdat") {
        $self->send_(503, "Error: bad sequence of commands", "5.5.1");
        return;
    }
    if ($self->{transaction}) {
        $self->send_(503, "Bad sequence of commands", "5.5.1");
        return;
    }
    # additional tests for atrn
    if ($self->{ESMTP} && ! $self->{auth_given} && $command eq "ATRN") {
        $self->send_(530, "Authentication required", "5.5.1");
        return;
    }
    $self->{close_connection} = 1;
    $self->send_(250, "OK now reversing the connection", "2.0.0");
    # set up local timeout handler
    eval {
        local $SIG{'ALRM'} = sub { die "TIMEOUT" };
        alarm($self->{timeout});
        $line = $self->recv_();
        if ($line =~ /\A220[\s]+/) {
            # try ehlo first
            $self->send_("000", "EHLO $self->{fqdn_hostname}");
            alarm($self->{timeout});
            $line = $self->recv_();
            alarm($self->{timeout});
            if ($line =~ /\A250-/) {
                $ehlo = 1;
                while ($line =~ /\A250-/) {
                    alarm($self->{timeout});
                    $line = $self->recv_();
                    alarm($self->{timeout});
                    last if ($line =~ /\A250\s/);
                }
            }
            elsif ($line =~ /\A250\s/) {
                $ehlo = 1;
            }
            elsif ($line =~ /\A5\d\d\s/) {
                # try helo
                $self->send_("000", "HELO $self->{fqdn_hostname}");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A250-/) {
                    $helo = 1;
                    while ($line =~ /\A250-/) {
                        alarm($self->{timeout});
                        $line = $self->recv_();
                        alarm($self->{timeout});
                        last if ($line =~ /\A250\s/);
                    }
                }
                elsif ($line =~ /\A250\s/) {
                    $helo = 1;
                }
                else {
                    # wrong reply to helo
                    return;
                }
            }
            else {
                # wrong status codes -> close the connection
                return;
            }
            # mail from
            if ($ehlo || $helo) {
                $self->send_("000", "MAIL FROM:<foo\@bar.org>");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A25\d\s/) {
                    $mail = 1;
                }
                else {
                    return;
                }
            }
            # rcpt to
            if (($ehlo || $helo) && $mail) {
                $self->send_("000", "RCPT TO:<bar\@foo.org>");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A25\d\s/) {
                    $rcpt = 1;
                }
                else {
                    return;
                }
            }
            # data
            if (($ehlo || $helo) && $mail && $rcpt) {
                $self->send_("000", "DATA");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A354\s/) {
                    $data = 1;
                }
                else {
                    return;
                }
            }
            # content
            if (($ehlo || $helo) && $mail && $rcpt && $data) {
                $self->send_("000", "Subject: INetSim test mail\r\n");
                $self->send_("000", "This is an INetSim test mail...\r\n");
                $self->send_("000", "\r\n.\r\n");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A25\d\s/ || $line =~ /\A(4|5)5\d\s/) {
                    $content = 1;
                }
            }
            else {
                return;
            }
            # quit
            if (($ehlo || $helo) && $mail && $rcpt && $data && $content) {
                $self->send_("000", "QUIT");
                alarm($self->{timeout});
                $line = $self->recv_();
                alarm($self->{timeout});
                if ($line =~ /\A221\s/) {        # for later use
                    $quit = 1;
                }
            }
        }
        alarm($self->{timeout});
    };
    alarm(0);
    if ($@ =~ /TIMEOUT/) {
        $self->{timed_out} = 1;
    }
}



sub STARTTLS {
    my ($self, $args) = @_;

    # RFC 4954 says:
    #
    # -----------------------------------------------------------------
    # "530 5.7.0  Authentication required
    #
    #  This response SHOULD be returned by any command other than AUTH,
    #  EHLO, HELO, NOOP, RSET, or QUIT..."
    # -----------------------------------------------------------------
    #
    # but this makes no sense for STARTTLS !!!?
    #
    #return if $self->auth_required;

    if (defined $args && $args && $args !~ /\A[\s\t]+\z/) {
        $self->syntax("STARTTLS");
        return;
    }

    if ($self->{using_tls}) {
        $self->send_("454", "TLS not available due to temporary reason");
        return;
    }

    $self->send_("220", "Ready to start TLS");
    if ($self->upgrade_to_ssl()) {
        # reset variables
        $self->{helo_given} = 0;
        $self->{sender_given} = 0;
        $self->{recipient_given} = 0;
        $self->{envelope_sender} = undef;
        $self->{envelope_recipient} = undef;
        $self->{transaction} = 0;
        $self->{transaction_type} = "";
        $self->{bdat_last} = 0;
        $self->{bdat_content} = "";
        $self->{bdat_incomplete} = 0;
        $self->{body_mime} = "";
        # deleting STARTTLS extension (rfc 2487, section 5.2)
        delete $SMTP_EXT{STARTTLS};
        # set tls flag
        $self->{using_tls} = 1;
        $status{tls_used} = 1;
        # log success
        $self->slog_("info: Connection successfully upgraded to SSL");
    }
    else {
        $self->slog_("info: Upgrade to SSL failed:  $self->{last_ssl_error}");
        $self->{close_connection} = 1;
    }
}



sub HELP {
    my ($self, $command) = @_;
    my $line = "";
    my @verbs = qw/HELO MAIL RCPT DATA RSET NOOP QUIT/;                # minimum requirement for smtp

    # add optional smtp verbs
    foreach my $key (sort keys %SMTP_EXT) {
        if ($key =~ /\A(HELP|VRFY|EXPN|SEND|SOML|SAML|TURN)\z/i) {
            push (@verbs, uc($key));
        }
    }
    # add optional esmtp verbs
    if ($self->{ESMTP}) {
        # add the keyword ehlo
        push (@verbs, "EHLO");
        foreach my $key (sort keys %SMTP_EXT) {
            if ($key =~ /\A(ETRN|AUTH|ATRN)\z/i) {
                push (@verbs, uc($key));
            }
        }
        # add BDAT, if chunking enabled
        if (defined $SMTP_EXT{CHUNKING}) {
            push (@verbs, "BDAT");
        }
        # add STARTTLS if enabled
        if (defined $SMTP_EXT{STARTTLS}) {
            push (@verbs, "STARTTLS");
        }
    }

    # print topic help
    if (defined ($command) && $command ne "" && $command =~ /\A[A-Za-z0-9\-]{3,16}/) {
        $command = uc($command);
        foreach (@verbs) {
            if ($_ eq $command) {
                if ($command eq "HELO" || $command eq "EHLO") {
                    $self->send_("214-", "$command <hostname>");
                    $self->send_("214-", " This command is used to identify");
                    $self->send_("214",  " the client to the server.");
                    return;
                }
                elsif ($command =~ /\A(MAIL|SEND|SOML|SAML)\z/) {
                    $self->send_("214-", "$command FROM: <address>");
                    $self->send_("214-", " This command is used to initiate");
                    $self->send_("214",  " a mail transaction.");
                    return;
                }
                elsif ($command eq "RCPT") {
                    $self->send_("214-", "RCPT TO: <address>");
                    $self->send_("214-", " This command is used to identify");
                    $self->send_("214",  " an individual recipient.");
                    return;
                }
                elsif ($command eq "DATA") {
                    $self->send_("214-", "DATA");
                    $self->send_("214-", " This command causes the mail data to");
                    $self->send_("214",  " be appended to the mail data buffer.");
                    return;
                }
                elsif ($command eq "RSET") {
                    $self->send_("214-", "RSET");
                    $self->send_("214-", " This command specifies that the current");
                    $self->send_("214-", " mail transaction will be aborted. All");
                    $self->send_("214",  " buffers and state tables are cleared.");
                    return;
                }
                elsif ($command eq "NOOP") {
                    $self->send_("214-", "NOOP");
                    $self->send_("214-", " This command has no effect, but it may");
                    $self->send_("214",  " useful to prevent timeouts.");
                    return;
                }
                elsif ($command eq "HELP") {
                    $self->send_("214-", "HELP [<topic>]");
                    $self->send_("214-", " This command prints helpful information");
                    $self->send_("214",  " about supported commands.");
                    return;
                }
                elsif ($command eq "QUIT") {
                    $self->send_("214-", "QUIT");
                    $self->send_("214-", " This command closes the");
                    $self->send_("214",  " transmission channel.");
                    return;
                }
                elsif ($command eq "VRFY") {
                    $self->send_("214-", "VRFY <address>");
                    $self->send_("214-", " This command asks the receiver to");
                    $self->send_("214-", " confirm that the argument identifies");
                    $self->send_("214",  " a user or mailbox.");
                    return;
                }
                elsif ($command eq "EXPN") {
                    $self->send_("214-", "EXPN <mailing list>");
                    $self->send_("214-", " This command asks the receiver to");
                    $self->send_("214-", " confirm that the argument identifies");
                    $self->send_("214",  " a mailing list.");
                    return;
                }
                elsif ($command eq "TURN") {
                    $self->send_("214-", "TURN");
                    $self->send_("214-", " This command reverses");
                    $self->send_("214",  " the connection.");
                    return;
                }
                elsif ($command eq "ETRN") {
                    $self->send_("214-", "ETRN [<option character>] <domain>]");
                    $self->send_("214-", " This command starts the remote queue");
                    $self->send_("214",  " processing for the specified domain.");
                    return;
                }
                elsif ($command eq "AUTH") {
                    $self->send_("214-", "AUTH <mechanism> [<initial-response>]");
                    $self->send_("214-", " The command indicates an authentication");
                    $self->send_("214",  " mechanism to the server.");
                    return;
                }
                elsif ($command eq "ATRN") {
                    $self->send_("214-", "ATRN <domain>");
                    $self->send_("214-", " This command reverses");
                    $self->send_("214",  " the connection.");
                    return;
                }
                elsif ($command eq "BDAT") {
                    $self->send_("214-", "BDAT <chunk size> [LAST]");
                    $self->send_("214-", " This command causes the chunk to be");
                    $self->send_("214",  " appended to the mail data buffer.");
                    return;
                }
                elsif ($command eq "STARTTLS") {
                    $self->send_("214-", "STARTTLS");
                    $self->send_("214-", " This command starts");
                    $self->send_("214",  " the TLS negotiation.");
                    return;
                }
            }
        }
        # special topic not found, so jump to general help now :-)
    }

    # print general help
    $self->send_("214-", "Commands supported:");
    while () {
        foreach (1..4) {
            $line .= shift(@verbs) . " " if (@verbs);
        }
        if ($line) {
            $line =~ s/[\s]+\z//;
            $self->send_("214-", "    $line");
            $line = "";
        }
        last if (! @verbs);
    }
    $self->send_("214",  "For more info use \"HELP <topic>\".");
}



sub helo_required {
    my $self = shift;

    if ($self->{helo_required} && ! $self->{helo_given}) {
        if ($self->{ESMTP}) {
            $self->send_(503, "Error: send HELO/EHLO first", "5.5.2");
        }
        else {
            $self->send_(503, "Error: send HELO first");
        }
        return 1;
    }
    return 0;
}



sub auth_required {
    my $self = shift;

    if ($self->{ESMTP} && $self->{auth_required} && ! $self->{auth_given}) {
        $self->send_(530, "Authentication required", "5.7.0");
        return 1;
    }
    return 0;
}



sub get_parameters {                # only for MAIL/SEND/SOML/SAML/RCPT/VRFY/EXPN !!!
    my ($self, $command, $string) = @_;
    my @args = ();
    my $address;

    return undef if (! defined ($command) || $command eq "" || $command !~ /\A(MAIL|SEND|SOML|SAML|RCPT|VRFY|EXPN)\z/i);
    $command = uc($command);
    # clear old parameters
    if ($command =~ /\A(MAIL|SEND|SOML|SAML)\z/) {
        %MAIL_PARAM = ();
    }
    elsif ($command eq "RCPT") {
        %RCPT_PARAM = ();
    }
    elsif ($command eq "VRFY") {
        %VRFY_PARAM = ();
    }
    elsif ($command eq "EXPN") {
        %EXPN_PARAM = ();
    }
    $self->{invalid_keyword} = 0;
    if (defined ($string) && $string ne "") {
        $string =~ s/[\s]+/\ /g;
        $string =~ s/\A[\s]+//;
        $string =~ s/[\s]+\z//;
        @args = split (/[\s]+/, $string);
        # return undef if empty (error)
        return undef if (! @args);
        # first argument should be the address
        $address = shift (@args);
        foreach (@args) {
            s/\A[\=]+//;
            my ($key, $value);
            # parameter=value        (with one or more values)
            if (/\A[\x21-\x7E]+\=[\x21-\x7E]+\z/) {
                ($key, $value) = split (/[\=]+/, $_, 2);
            }
            # parameter                (without values)
            elsif (/\A([\x21-\x7E]+)\z/) {
                $key = $1;
                $value = "";
            }
            # invalid -> ignore
            else {
                next;
            }
            if (defined ($key) && $key ne "") {
                $key = uc($key);
                if ($command =~ /\A(MAIL|SEND|SOML|SAML)\z/ && ! defined ($MAIL_PARAM{$key})) {
                    if ($self->{mail_keywords} !~ $key) {
                        $self->{invalid_keyword} = 1;
                        last;
                    }
                    $MAIL_PARAM{$key} = $value;
                }
                elsif ($command eq "RCPT" && ! defined ($RCPT_PARAM{$key})) {
                    if ($self->{rcpt_keywords} !~ $key) {
                        $self->{invalid_keyword} = 1;
                        last;
                    }
                    $RCPT_PARAM{$key} = $value;
                }
                elsif ($command eq "VRFY" && ! defined ($VRFY_PARAM{$key})) {
                    if ($self->{vrfy_keywords} !~ $key) {
                        $self->{invalid_keyword} = 1;
                        last;
                    }
                    $VRFY_PARAM{$key} = $value;
                }
                elsif ($command eq "EXPN" && ! defined ($EXPN_PARAM{$key})) {
                    if ($self->{expn_keywords} !~ $key) {
                        $self->{invalid_keyword} = 1;
                        last;
                    }
                    $EXPN_PARAM{$key} = $value;
                }
            }
        }
    }
    # always give the first argument (address) back - or undef if error
    return $address;
}



sub search_checkpoint {
    my ($self, $transid, $sender) = @_;
    my %checkpoint = ();
    my $addr = "";
    my $offset = 0;
    my $messageid = "";
    my $queueid = "";
    my $dummy = "";
    my $stat = "";
    my $search = qr/\sSENDER\=$sender\,\sTRANSID\=$transid/;

    $self->{checkpoint_found} = 0;
    $self->{transaction_offset} = 0;
    $self->{transaction_queueid} = "";
    $self->{transaction_messageid} = "";
    $self->{transaction_recipient} = "";
    if (open(MBOX, "$self->{mboxFile}")) {
        alarm($self->{timeout});
        while (<MBOX>) {
            $stat = "";
            $dummy = "";
            $queueid = "";
            if (/\ADelivered-To: (.*)\z/) {
                $addr = $1;
            }
            elsif (/\AX-INetSim-Id: (.*)\z/) {
                $messageid = $1;
            }
            # search for checkpoints
            elsif ($search && /\AX-Checkpoint: (YES|NO)\, OFFSET\=([\d]+)\, QUEUEID\=(.*?)\, SENDER\=(.*?)\, TRANSID\=(.*)\z/) {
                $stat = $1;
                # add checkpoint
                if ($stat eq "YES") {
                    $checkpoint{$messageid} = "$2:$3:$addr:$4:$5";
                }
                # delete checkpoint
                else {
                    $dummy = ":$3:$addr:$4:$5";
                    if (defined ($checkpoint{$messageid}) && $checkpoint{$messageid} =~ /\A\d+$dummy\z/) {
                        delete $checkpoint{$messageid};
                    }
                }
            }
        }
        close MBOX;
        # if more than one checkpoint, search the last known offset
        foreach $messageid (keys %checkpoint) {
            ($offset, $queueid, $addr, $dummy) = split (/:/, $checkpoint{$messageid}, 4);
            if ($offset > $self->{transaction_offset}) {
                $self->{checkpoint_found} = 1;
                $self->{transaction_offset} = $offset;
                $self->{transaction_queueid} = $queueid;
                $self->{transaction_messageid} = $messageid;
                $self->{transaction_recipient} = $addr;
            }
        }
    }
}



sub write_message {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $line;
    my $first = 1;
    my $prev;
    my $last;
    my $header_field = 0;
    my $is_body = 0;
    my @raw = ();
    my @header = ();
    my @body = ();
    my $size = 0;
    my $offset = 0;
    my $queueid;
    my $message_id;

    if (defined ($msg)) {
        alarm($self->{timeout});
        $size = length($msg);
        $msg =~ s/\r\n/\n/g;
        $msg =~ s/\r//g;
#        my $oldfs = \z/;
#        \z/ = undef;
        @raw = split (/\n/, $msg);
#        \z/ = $oldfs;
        # Removing empty lines at the beginning
        while (defined ($raw[0]) && $raw[0] =~ /\A\z/) {
            shift (@raw);
        }
        # Removing empty lines at the end
        @raw = reverse (@raw);
        while (defined ($raw[0]) && $raw[0] =~ /\A\z/) {
            shift (@raw);
        }
        @raw = reverse (@raw);
        foreach $line (@raw) {
            # quote existing 'From ' lines
            if ($line =~ /\AFrom\s.*/) {
                $line = ">" . $line;
            }
            # remove '.' from lines beginning with .
            elsif ($line =~ /\A\..+/) {
                $line =~ s/\A\.//;
            }
            # check for typical header syntax
            if (! $is_body && $line =~ /\A([a-zA-Z])([a-zA-Z0-9-_]+):\s([\x21-\x7E]+).*\z/) {
                $header_field = 1;
            }
            # header could be folded
            elsif (! $is_body && $header_field && $line =~ /\A[\s\t]+[\x21-\x7E]+.*\z/) {
                # do nothing
            }
            # may be end of header
            elsif (! $is_body && $header_field && $line =~ /\A\z/) {
                $is_body = 1;
                $header_field = 0;
            }
            # check for anything after <CRLF> (but not in the first line), that should be the body
            elsif (! $first && $prev =~ /\A\z/ && length($line)) {
                $is_body = 1;
                $header_field = 0;
            }
            # giving up... handle more data as body
            else {
                $is_body = 1;
                $header_field = 0;
            }
            # push header line
            if (! $is_body && $header_field && $line !~ /\A\z/) {
                push (@header, $line);
            }
            # push body line
            else {
                push (@body, $line);
            }
            # delete the first-line-flag :-)
            if ($first) { $first = 0; };
            $prev = $line;
        }
        ### Removing empty lines at the beginning
        while (defined ($body[0]) && $body[0] =~ /\A\z/) {
            shift (@body);
        }
        ### generate queue and message id
        if ($self->{transaction_type} eq "data" && $self->{checkpoint_found} && $self->{transaction_queueid}) {
            $queueid = $self->{transaction_queueid};
            $message_id = $self->{transaction_messageid};
            $self->{envelope_recipient} = $self->{transaction_recipient};
        }
        else {
            srand(time() ^($$ + ($$ <<15)));
            $queueid = &dec2hex(int(rand(65534) + 1)) . &dec2hex(int(rand(65534) + 1 ));
            my $sha = Digest::SHA->new();
            $sha->add(int(rand(100000000)));
            $sha->add(time());
            $message_id = "<$queueid-" . $sha->hexdigest . "\@$self->{fqdn_hostname}>";
        }
        ### some essential message headers
        my @hdr = ();
        push (@hdr, "From " . $self->{envelope_sender} . "  " . scalar localtime(INetSim::FakeTime::get_faketime()));
        if ($self->{envelope_sender} eq "MAILER-DAEMON") {
            push (@hdr, "Return-Path: <>");
        }
        else {
            push (@hdr, "Return-Path: <" . $self->{envelope_sender} . ">");
        }
        push (@hdr, "Envelope-To: " . $self->{envelope_recipient});
        # received line
        push (@hdr, "Received: from victim ([$rhost])");
        push (@hdr, "\tby cheater (INetSim) with $self->{mailTransmissionType} id $queueid");
        push (@hdr, "\tfor <$self->{envelope_recipient}>; " . &rfc2822_date(INetSim::FakeTime::get_faketime()));
        # unique message-id
        push (@hdr, "X-INetSim-Id: $message_id");
        # write additional headers for CHUNKING
        if ($self->{transaction_type} eq "bdat") {
            if ($self->{bdat_incomplete}) {
                push (@hdr, "X-Chunking: YES, INCOMPLETE");
            }
            else {
                push (@hdr, "X-Chunking: YES, COMPLETE");
            }
        }
        # write additional headers for CHECKPOINT/RESTART
        if ($self->{transaction_type} eq "data") {
            if ($self->{transid}) {
                $offset = int($self->{transaction_offset} + $size);
                if ($self->{data_incomplete}) {
                    push (@hdr, "X-Checkpoint: YES, OFFSET=$offset, QUEUEID=$queueid, SENDER=$self->{envelope_sender}, TRANSID=$self->{transid}");
                }
                else {
                    push (@hdr, "X-Checkpoint: NO, OFFSET=$offset, QUEUEID=$queueid, SENDER=$self->{envelope_sender}, TRANSID=$self->{transid}");
                }
            }
        }
        ### Now write contents to mbox-file
        if (! open(MBOX, ">>$self->{mboxFile}")) {
            return undef;
        }
        foreach (@hdr) {
            print MBOX "$_\n";
        }
        alarm($self->{timeout});
        # message has a header, therefore add content
        if (@header) {
            foreach (@header) {
                next if (/\A\z/);
                print MBOX "$_\n";
            }
        }
        # newline after header
        print MBOX "\n";
        alarm($self->{timeout});
        # add message body, if not empty...
        foreach (@body) {
            print MBOX "$_\n";
        }
        alarm($self->{timeout});
        # else add a second newline
        print MBOX "\n";
        # close mbox file
        close MBOX;
        # log the message id
        $self->slog_("info: Message id: $message_id");
        # return queue id
        return $queueid;
    }
    return undef;
}



sub syntax {
    my ($self, $command) = @_;

    if (defined ($command) && $command) {
        $command = uc($command);
        if ($command =~ /\A(HELO|EHLO)\z/) {
            $self->send_(501, "Syntax: $command hostname");
        }
        elsif ($command =~ /\A(MAIL|SEND|SOML|SAML)\z/) {
            $self->send_(501, "Syntax: $command FROM:<address>", "5.5.4");
        }
        elsif ($command eq "RCPT") {
            $self->send_(501, "Syntax: RCPT TO:<address>", "5.5.4");
        }
        elsif ($command =~ /\A(RSET|DATA|NOOP|QUIT|TURN|STARTTLS)\z/) {
            $self->send_(501, "Syntax: $command", "5.5.4");
        }
        elsif ($command eq "VRFY") {
            $self->send_(501, "Syntax: VRFY <address>", "5.5.4");
        }
        elsif ($command eq "EXPN") {
            $self->send_(501, "Syntax: EXPN <mailing list>", "5.5.4");
        }
        elsif ($command eq "ETRN") {
            $self->send_(501, "Syntax: ETRN [<option character>] <domain>", "5.5.4");
        }
        elsif ($command eq "AUTH") {
            $self->send_(501, "Syntax: AUTH <mechanism> [<initial-response>]", "5.5.4");
        }
        elsif ($command eq "ATRN") {
            $self->send_(501, "Syntax: ATRN <domain>", "5.5.4");
        }
        elsif ($command eq "BDAT") {
            $self->send_(501, "Syntax: BDAT <chunk size> [LAST]", "5.5.4");
        }
    }
}



sub dec2hex {
    my $str = uc(sprintf("%lx", shift));
    my $padding = 0;

    $padding = 2 - length($str) % 2 if length($str) % 2;
    return substr('00', 0, $padding) . $str;
}



sub b64_dec {
    my $string = shift;
    my $length;
    my $out;

    (defined $string && $string) or return 0;
    (length($string) % 4 == 0) or return 0;
    ($string =~ /\A[A-Za-z0-9\+\/]+([\=]{0,2})\z/) or return 0;

    return decode_base64($string);
}




sub rfc2822_date {
    my $timestamp = shift;
    my @days=qw/Sun Mon Tue Wed Thu Fri Sat/;
    my @months=qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;

    if (defined ($timestamp) && $timestamp) {
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) = gmtime($timestamp);
        $year += 1900;
        $hour = substr("0$hour", -2);
        $min = substr("0$min", -2);
        $sec = substr("0$sec", -2);
        return "$days[$wday], $mday $months[$mon] $year $hour:$min:$sec -0000"; # always utc !!
    }
    return 0;
}



sub register_extensions {
    my $self = shift;
    my %conf_ext;

    if ($self->{ssl_enabled}) {
        %conf_ext = INetSim::Config::getConfigHash("SMTPS_Service_Extensions");
    }
    else {
        %conf_ext = INetSim::Config::getConfigHash("SMTP_Service_Extensions");
    }

    $self->{mail_keywords} = "";
    $self->{rcpt_keywords} = "";
    $self->{vrfy_keywords} = "";
    $self->{expn_keywords} = "";
    foreach (keys %conf_ext) {
        if (defined ($EXT_AVAIL{$_}) && $EXT_AVAIL{$_}) {
            if (! defined ($SMTP_EXT{$_})) {
                # for compatibility with old option 'smtp_auth_reversibleonly'
                if ($_ eq "AUTH" && $self->{auth_reversible_only}) {
                    $conf_ext{$_} =~ s/CRAM-(MD5|SHA1)([\s]+)?//g;
                    # do not register without any mechanism
                    next if ($conf_ext{$_} !~ /[A-Za-z0-9]+/);
                }
                $conf_ext{$_} =~ s/[\s]+\z//;
                # parameters are allowed
                if ($EXT_AVAIL{$_} == 2) {
                    $SMTP_EXT{$_} = $conf_ext{$_};
                }
                # parameters are not allowed
                else {
                    $SMTP_EXT{$_} = "";
                }
                # register keywords for mail
                if (defined($MAIL_AVAIL{$_})) {
                    $self->{mail_keywords} .= join (",", $MAIL_AVAIL{$_}) . ",";
                }
                # register keywords for rcpt
                if (defined($RCPT_AVAIL{$_})) {
                    $self->{rcpt_keywords} .= join (",", $RCPT_AVAIL{$_}) . ",";
                }
                # register keywords for vrfy
                if (defined($VRFY_AVAIL{$_})) {
                    $self->{vrfy_keywords} .= join (",", $VRFY_AVAIL{$_}) . ",";
                }
                # register keywords for expn
                if (defined($EXPN_AVAIL{$_})) {
                    $self->{expn_keywords} .= join (",", $EXPN_AVAIL{$_}) . ",";
                }
            }
        }
    }
    $self->{mail_keywords} =~ s/\,\z//;
    $self->{rcpt_keywords} =~ s/\,\z//;
    $self->{vrfy_keywords} =~ s/\,\z//;
    $self->{expn_keywords} =~ s/\,\z//;
    # resolve possible dependencies below...
    # disable ATRN, if AUTH is not set
    if (defined $SMTP_EXT{ATRN} && ! defined $SMTP_EXT{AUTH}) {
        delete $SMTP_EXT{ATRN};
    }
    # don't force authentication without AUTH extension ;-)
    if (! defined $SMTP_EXT{AUTH}) {
        $self->{auth_required} = 0;
    }
    # disable BINARYMIME, if CHUNKING is not set
    if (defined ($SMTP_EXT{BINARYMIME}) && ! defined ($SMTP_EXT{CHUNKING})) {
        delete $SMTP_EXT{BINARYMIME};
    }
#    # according to RFC 2821, section '4.5.1 Minimum Implementation': "...MUST be supported...VRFY..."
#    if ($self->{ESMTP} && ! defined ($SMTP_EXT{VRFY})) {
#        $SMTP_EXT{VRFY} = "";
#    }
    # if SIZE is set with value, then set maximum message size (must be >= 1MB)
    if (defined ($SMTP_EXT{SIZE}) && $SMTP_EXT{SIZE} && $SMTP_EXT{SIZE} =~ /\A([\d]{7,})\z/) {
        $self->{max_message_size} = $1;
    }
    else {
        # set default maximum size to 10 MB
        $self->{max_message_size} = 10485760;
    }
    # set maximum chunk length for chunking to 25% from max_message_size
    $self->{max_chunk_length} = int($self->{max_message_size} / 4);
    # check FUTURERELEASE options (required !)
    if (defined ($SMTP_EXT{FUTURERELEASE}) && (! $SMTP_EXT{FUTURERELEASE} || $SMTP_EXT{FUTURERELEASE} !~ /\A([\d]+)\s([\d]+)\z/)) {
        # set 'max-future-release-interval' to two weeks and 'max-future-release-date-time' to faketime_max
        my $max_date = INetSim::Config::getConfigParameter("Faketime_Max");
        $max_date = 999999999 if (! $max_date || $max_date > 999999999);        # check maximum allowed value
        $SMTP_EXT{FUTURERELEASE} = "1209600 $max_date";
    }
    # disable STARTTLS, if SSL library not found or certfile/keyfile not found/not readable/empty
    if (! $SSL || ! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
        delete $SMTP_EXT{STARTTLS};
    }
    # warn about missing dh file and disable
    if (defined $self->{ssl_dh} && (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh} || ! -s $self->{ssl_dh})) {
        INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
        $self->{ssl_dh} = undef;
    }
    # disable STARTTLS, if already using SSL
    if ($self->{ssl_enabled}) {
        delete $SMTP_EXT{STARTTLS};
    }
    # set mail transmission type
    $self->{mailTransmissionType} = "SMTP";
    if ($self->{ESMTP}) {
        if (defined $SMTP_EXT{STARTTLS}) {
            $self->{mailTransmissionType} .= "S";
        }
        if (defined $SMTP_EXT{AUTH} && $SMTP_EXT{AUTH} ne "") {
            $self->{mailTransmissionType} .= "A";
        }
        if (defined $SMTP_EXT{UTF8SMTP}) {
            $self->{mailTransmissionType} = "UTF8" . $self->{mailTransmissionType};
        }
        else {
            $self->{mailTransmissionType} = "E" . $self->{mailTransmissionType};
        }
    }
}



sub upgrade_to_ssl {
    my $self = shift;
    my %ssl_params = (  SSL_version             => "SSLv23",
                        SSL_cipher_list         => "ALL",
                        SSL_server              => 1,
                        SSL_use_cert            => 1,
                        SSL_key_file            => $self->{ssl_key},
                        SSL_cert_file           => $self->{ssl_crt} );

    $self->{last_ssl_error} = "";

    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $ssl_params{'SSL_dh_file'} = $self->{ssl_dh};
    }

    my $result = IO::Socket::SSL::socket_to_SSL( $self->{server}->{client}, %ssl_params );

    if (defined $result) {
        $status{tls_cipher} = lc($result->get_cipher());
        return 1;
    }
    else {
        $self->{last_ssl_error} = IO::Socket::SSL::errstr();
        return 0;
    }
}



sub error_exit {
    my ($self, $msg) = @_;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

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
