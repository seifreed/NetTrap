# -*- perl -*-
#
# INetSim::FTP - A fake FTP server
#
# RFC 959 (and others) - FILE TRANSFER PROTOCOL (FTP)
#
# (c)2008-2019 Matthias Eckert, Thomas Hungenberg
#
#############################################################

package INetSim::FTP;

use strict;
use warnings;
use base qw(INetSim::GenericServer);
use IO::Socket;
use Digest::SHA;
use Fcntl ':flock';

my $SSL = 0;
eval { require IO::Socket::SSL; };
if (! $@) { $SSL = 1; };

my %VFS;

sub configure_hook {
    my $self = shift;
    my ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks, $grpname) = undef;

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
    # default timeout
    $self->{timeout} = INetSim::Config::getConfigParameter("Default_TimeOut");
    # max childs
    $self->{maxchilds} = INetSim::Config::getConfigParameter("Default_MaxChilds");
    # cert directory
    $self->{cert_dir} = INetSim::Config::getConfigParameter("CertDir");

    if (defined $self->{server}->{'SSL'} && $self->{server}->{'SSL'}) {
        $self->{servicename} = INetSim::Config::getConfigParameter("FTPS_ServiceName");
        if (! $SSL) {
            INetSim::Log::MainLog("failed! Library IO::Socket::SSL not installed", $self->{servicename});
            exit 1;
        }
        $self->{ssl_key} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("FTPS_KeyFileName") ? INetSim::Config::getConfigParameter("FTPS_KeyFileName") : INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("FTPS_CrtFileName") ? INetSim::Config::getConfigParameter("FTPS_CrtFileName") : INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined INetSim::Config::getConfigParameter("FTPS_DHFileName") ? INetSim::Config::getConfigParameter("FTPS_DHFileName") : INetSim::Config::getConfigParameter("Default_DHFileName"));
        if (! -f $self->{ssl_key} || ! -r $self->{ssl_key} || ! -f $self->{ssl_crt} || ! -r $self->{ssl_crt} || ! -s $self->{ssl_key} || ! -s $self->{ssl_crt}) {
            INetSim::Log::MainLog("failed! Unable to read SSL certificate files", $self->{servicename});
            exit 1;
        }
        $self->{ssl_enabled} = 1;
        $self->{server}->{port}   = INetSim::Config::getConfigParameter("FTPS_BindPort");  # bind to port
        $self->{dataport} = INetSim::Config::getConfigParameter("FTPS_DataPort");
        # data_port should be ftp_port - 1
        # workaround for: server_port changed, but data_port has already default values
        if ($self->{server}->{port} != 990 && $self->{dataport} == 989) {
            $self->{dataport} = $self->{server}->{port} - 1;
        }
        $self->{sessionfile} = INetSim::Config::getConfigParameter("FTPS_UploadDir") . "/session.dat";
        # version
        $self->{version} = INetSim::Config::getConfigParameter("FTPS_Version");
        # banner
        $self->{banner} = INetSim::Config::getConfigParameter("FTPS_Banner");
        $self->{document_root} = INetSim::Config::getConfigParameter("FTPS_DocumentRoot");
        $self->{upload_dir} = INetSim::Config::getConfigParameter("FTPS_UploadDir");
        # allow recursive delete
        $self->{recursive_delete} = INetSim::Config::getConfigParameter("FTPS_RecursiveDelete");
        # maximum file size
        $self->{max_filesize} = INetSim::Config::getConfigParameter("FTPS_MaxFileSize");
    }
    else {
        $self->{servicename} = INetSim::Config::getConfigParameter("FTP_ServiceName");
        $self->{ssl_enabled} = 0;
        $self->{server}->{port}   = INetSim::Config::getConfigParameter("FTP_BindPort");  # bind to port
        $self->{dataport} = INetSim::Config::getConfigParameter("FTP_DataPort");
        # data_port should be ftp_port - 1
        # workaround for: server_port changed, but data_port has already default values
        if ($self->{server}->{port} != 21 && $self->{dataport} == 20) {
            $self->{dataport} = $self->{server}->{port} - 1;
        }
        $self->{sessionfile} = INetSim::Config::getConfigParameter("FTP_UploadDir") . "/session.dat";
        # version
        $self->{version} = INetSim::Config::getConfigParameter("FTP_Version");
        # banner
        $self->{banner} = INetSim::Config::getConfigParameter("FTP_Banner");
        $self->{document_root} = INetSim::Config::getConfigParameter("FTP_DocumentRoot");
        $self->{upload_dir} = INetSim::Config::getConfigParameter("FTP_UploadDir");
        # allow recursive delete
        $self->{recursive_delete} = INetSim::Config::getConfigParameter("FTP_RecursiveDelete");
        # maximum file size
        $self->{max_filesize} = INetSim::Config::getConfigParameter("FTP_MaxFileSize");
        $self->{ssl_key} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("FTPS_KeyFileName") ? INetSim::Config::getConfigParameter("FTPS_KeyFileName") : INetSim::Config::getConfigParameter("Default_KeyFileName"));
        $self->{ssl_crt} = $self->{cert_dir} . (defined INetSim::Config::getConfigParameter("FTPS_CrtFileName") ? INetSim::Config::getConfigParameter("FTPS_CrtFileName") : INetSim::Config::getConfigParameter("Default_CrtFileName"));
        $self->{ssl_dh} = (defined INetSim::Config::getConfigParameter("FTPS_DHFileName") ? INetSim::Config::getConfigParameter("FTPS_DHFileName") : INetSim::Config::getConfigParameter("Default_DHFileName"));
    }

    # warn about missing dh file and disable
    if (defined $self->{ssl_dh} && $self->{ssl_dh}) {
        $self->{ssl_dh} = $self->{cert_dir} . $self->{ssl_dh};
        if (! -f $self->{ssl_dh} || ! -r $self->{ssl_dh}) {
            INetSim::Log::MainLog("Warning: Unable to read Diffie-Hellman parameter file '$self->{ssl_dh}'", $self->{servicename});
            $self->{ssl_dh} = undef;
        }
    }

    $self->{sessionfile} =~ /\A(.*)\z/; # evil untaint!
    $self->{sessionfile} = $1;

    # check DocumentRoot directory
    if (! -d $self->{document_root}) {
        INetSim::Log::MainLog("failed! DocumentRoot directory '$self->{document_root}' does not exist", $self->{servicename});
        exit 1;
    }

    # check Upload directory
    $self->{upload_dir} =~ /\A(.*)\z/; # evil untaint!
    $self->{upload_dir} = $1;
    if (! -d $self->{upload_dir}) {
        INetSim::Log::MainLog("failed! Upload directory '$self->{upload_dir}' does not exist", $self->{servicename});
        exit 1;
    }

    $gid = getgrnam($self->{server}->{group});
    if (! defined $gid) {
        INetSim::Log::MainLog("Warning: Unable to get GID for group '$self->{server}->{group}'", $self->{servicename});
    }
    chown -1, $gid, $self->{upload_dir};
    ($dev, $inode, $mode, $nlink, $uid, $gid, $rdev, $size, $atime, $mtime, $ctime, $blksize, $blocks) = stat $self->{upload_dir};

    # check group owner
    $grpname = getgrgid $gid;
    if ($grpname ne $self->{server}->{group}) {
        INetSim::Log::MainLog("Warning: Group owner of Upload directory '$self->{upload_dir}' is not '$self->{server}->{group}' but '$grpname'", $self->{servicename});
    }
    # check for group r/w permissions
    if ((($mode & 0060) >> 3) != 6) {
        INetSim::Log::MainLog("Warning: No group r/w permissions on Upload directory '$self->{upload_dir}'", $self->{servicename});
    }

    # initialize random number generator
    srand(time() ^($$ + ($$ <<15)));

    # initialize the matrix :-)
    $self->init_VFS;
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

    $self->{username} = "";
    $self->{password} = "";
    $self->{authenticated} = 0;
    $self->{active} = 0;        # for later use (PASV)
    $self->{passive} = 0;
    $self->{current_dir} = "";
    # set default type to ascii non-print
    $self->{type} = "ASCII";
    $self->{typeparam} = "N";
    # set default structure to file
    $self->{stru} = "F";
    # set default transfer mode to stream
    $self->{mode} = "S";
    # count all actions
    $self->{count_created} = 0;
    $self->{count_deleted} = 0;
    $self->{count_retrieved} = 0;

    my $stat_success = 0;
    my $credentials = "";

    if ($self->{ssl_enabled} && ! $self->upgrade_to_ssl()) {
        $self->slog_("connect");
        $self->slog_("info: Error setting up SSL:  $self->{last_ssl_error}");
        $self->slog_("disconnect");
        $self->slog_("stat: 0");
        return;
    }
    if ($self->{server}->{numchilds} >= $self->{maxchilds}) {
        $self->send_("421 Maximum number of connections ($self->{maxchilds}) exceeded.");
        $self->slog_("stat: 0");
        return;
    }
    my $line = "";
    eval {
        local $SIG{'ALRM'} = sub { die "TIMEOUT" };
        alarm($self->{timeout});
        $self->slog_("connect");
        ### Server Greeting
        $self->send_("220 $self->{banner}");
        ### Now wait for command
        while ($line = <$client>){
            chomp($line);
            $line =~ s/\r\z//g;
            $line =~ s/[\r\n]+//g;
            alarm($self->{timeout});
            $self->slog_("recv: $line");
            if (defined ($line) && $line =~ /\AQUIT(|([\s]+)(.*))\z/i) {
                $self->QUIT;
                last;
            }
            elsif (defined ($line) && $line =~ /\AUSER[\s\t]+(.*)\z/i) {
                $self->USER($1);
            }
            elsif (defined ($line) && $line =~ /\APASS[\s\t]+(.*)\z/i) {
                $self->PASS($1);
                if ($self->{authenticated}) {
                    $stat_success = 1;
                    $credentials = "$self->{username}:$self->{password}";
                }
            }
            elsif (defined ($line) && $line =~ /\ASYST(|([\s\t]+)(.*))\z/i) {
                $self->SYST;
            }
            elsif (defined ($line) && $line =~ /\ALIST(|[\s\t]+(.*))\z/i) {
                $self->LIST($2);
            }
            elsif (defined ($line) && $line =~ /\ANLST(|[\s\t]+(.*))\z/i) {
                $self->NLST($2);
            }
            elsif (defined ($line) && $line =~ /\APORT[\s\t]+([\d\,]+)\z/i) {
                $self->PORT($1);
            }
            elsif (defined ($line) && $line =~ /\ACWD[\s\t]+(.*)\z/i) {
                $self->CWD($1);
            }
            elsif (defined ($line) && $line =~ /\ACDUP(|([\s\t]+)(.*))\z/i) {
                $self->CDUP;
            }
            elsif (defined ($line) && $line =~ /\ARMD[\s\t]+(.*)\z/i) {
                $self->RMD($1);
            }
            elsif (defined ($line) && $line =~ /\AMKD[\s\t]+(.*)\z/i) {
                $self->MKD($1);
            }
            elsif (defined ($line) && $line =~ /\APWD(|([\s\t]+)(.*))\z/i) {
                $self->PWD;
            }
#            elsif (defined ($line) && $line =~ /\AABOR(|([\s\t]+)(.*))\z/i) {
#                $self->ABOR;
#            }
            elsif (defined ($line) && $line =~ /\ADELE[\s\t]+(.*)\z/i) {
                $self->DELE($1);
            }
            elsif (defined ($line) && $line =~ /\ATYPE[\s\t]+(\w(\s[\w\d])?)\z/i) {
                $self->TYPE($1);
            }
            elsif (defined ($line) && $line =~ /\ASTRU[\s\t]+(\w)\z/i) {
                $self->STRU($1);
            }
            elsif (defined ($line) && $line =~ /\AMODE[\s\t]+(\w)\z/i) {
                $self->MODE($1);
            }
            elsif (defined ($line) && $line =~ /\ANOOP(|([\s\t]+)(.*))\z/i) {
                $self->NOOP;
            }
            elsif (defined ($line) && $line =~ /\AHELP(|[\s\t]+(.*))\z/i) {
                $self->HELP($2);
            }
            elsif (defined ($line) && $line =~ /\ASTAT(|[\s\t]+(.*))\z/i) {
                $self->STAT($2);
            }
            elsif (defined ($line) && $line =~ /\ASTOR[\s\t]+(.*)\z/i) {
                $self->STOR($1);
            }
#            elsif (defined ($line) && $line =~ /\ASTOU(|[\s\t]+(.*))\z/i) {
#                $self->STOU($2);
#            }
            elsif (defined ($line) && $line =~ /\ARETR[\s\t]+(.*)\z/i) {
                $self->RETR($1);
            }
#            elsif (defined ($line) && $line =~ /\AREIN(|([\s\t]+)(.*))\z/i) {
#                $self->REIN;
#            }
#            elsif (defined ($line) && $line =~ /\AACCT(|[\s\t]+(.*))\z/i) {
#                $self->ACCT($2);
#            }
#            elsif (defined ($line) && $line =~ /\AREST(|[\s\t]+(.*))\z/i) {
#                $self->REST($2);
#            }
#            elsif (defined ($line) && $line =~ /\AAPPE(|[\s\t]+(.*))\z/i) {
#                $self->APPE($2);
#            }
#            elsif (defined ($line) && $line =~ /\ARNFR(|[\s\t]+(.*))\z/i) {
#                $self->RNFR($2);
#            }
#            elsif (defined ($line) && $line =~ /\ARNTO(|[\s\t]+(.*))\z/i) {
#                $self->RNTO($2);
#            }
#            elsif (defined ($line) && $line =~ /\ASITE(|[\s\t]+(.*))\z/i) {
#                $self->SITE($2);
#            }
            else {
                $self->send_("500 Unknown command.");
            }
            alarm($self->{timeout});
        }
    };
    alarm(0);
    if ($@ =~ /TIMEOUT/) {
        $self->send_("421 Error: timeout exceeded");
        $self->slog_("disconnect (timeout)");
    }
    else {
        $self->slog_("disconnect");
    }
    $self->_save_vfs_changes;
    $self->slog_("stat: $stat_success" . (($stat_success == 1) ? " created=$self->{count_created} deleted=$self->{count_deleted} retrieved=$self->{count_retrieved} creds=$credentials" : ""));
}


sub slog_ {
    my $self = shift;
    my $msg = shift;
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};

    if (defined ($msg)) {
        $msg =~ s/[\r\n]*//;
        INetSim::Log::SubLog("[$rhost:$rport] $msg", $self->{servicename}, $$);
    }
}


sub send_ {
    my $self = shift;
    my $msg = shift;
    my $client = $self->{server}->{client};

    if (defined ($msg) && $msg ne "") {
        $msg =~ s/[\r\n]*//;
        print $client "$msg\r\n";
        $self->slog_("send: $msg");
    }
}


sub QUIT {
    my $self = shift;

    $self->{username} = "";
    $self->{password} = "";
    $self->{authenticated} = 0;
    $self->{current_dir} = "";
    $self->send_("221 Goodbye.");
}


sub USER {
    my $self = shift;
    my $username = shift;

    $self->{username} = "";
    $self->{password} = "";
    $self->{authenticated} = 0;
    chomp($username);
    if (defined ($username) && $username) {
        $self->{username} = $username;
        $self->send_("331 Please specify the password.");
    }
    else {
        $self->send_("501 Syntax error in parameter.");
    }
}


sub PASS {
    my $self = shift;
    my $password = shift;

    $self->{password} = "";
    $self->{authenticated} = 0;
    if ($self->{username}) {
        chomp($password);
        if (defined ($password) && $password) {
            $self->{password} = $password;
            $self->{authenticated} = 1;
            $self->send_("230 Login successful.");
            $self->_read_vfs_changes;
        }
        else {
            $self->{username} = "";
            $self->send_("501 Syntax error in parameter.");
        }
    }
    else {
        $self->send_("503 Login with USER first.");
    }
}


sub SYST {
    my $self = shift;

    if ($self->{authenticated}) {
        $self->send_("215 UNIX Type: L8");
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub PORT {
    my $self = shift;
    my $port_args = shift;

    if ($self->{authenticated}) {
        $self->{active} = 0;
        $self->{passive} = 0;
        chomp($port_args);
        if (defined ($port_args) && $port_args && $port_args =~ /\A[\d]{1,3}\,[\d]{1,3}\,[\d]{1,3}\,[\d]{1,3}\,[\d]{1,3}\,[\d]{1,3}\z/) {
            my @byte = split (/\,/, $port_args, 6);
            foreach (@byte) {
                next if ($_ >= 0 && $_ <= 255);
                # else...
                $self->send_("500 Illegal PORT command.");
                return;
            }
            $self->{active} = 1;
            $self->{passive} = 0;
            $self->{data_host} = "$byte[0].$byte[1].$byte[2].$byte[3]";
            $self->{data_port} = int(($byte[4] * 256) + $byte[5]);
            $self->send_("200 PORT command successful.");
        }
        else {
            $self->send_("500 Illegal PORT command.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub LIST {
    my $self = shift;
    my $directory = shift;
    my $data_channel;
    my $ref;
    my %list;
    my $key;

    if (defined $directory) {
        # ignore options like "-aL"
        $directory =~ s/\A[\s]*\-[a-zA-Z]+[\s]*//;
        ($directory eq "") and ($directory = undef);
    }

    if ($self->{authenticated}) {
        if ($self->{active} && $self->{data_host} && $self->{data_port}) {
            $self->_read_vfs_changes;
            if (defined ($directory)) {
                chomp($directory);
            }
            $ref = $self->_vfs_list($directory);
            %list = %$ref;
            $self->send_("150 Opening ASCII mode data connection for file list.");
            eval {
                local $SIG{'ALRM'} = sub { die "TIMEOUT" };
                alarm($self->{timeout});
                $data_channel = $self->establish_data_channel;
                if ($data_channel) {
                    foreach $key (sort keys %list) {
                        print $data_channel "$list{$key}$key\r\n";
                    }
                    $self->slog_("send: <(DATA)>");
                    $self->close_data_channel($data_channel);
                    $self->send_("226 Transfer complete.");
                }
                else {
                    $self->send_("426 Failure writing network stream.");
                }
                alarm($self->{timeout});
            };
            alarm(0);
            if ($@ =~ /TIMEOUT/) {
                $self->close_data_channel($data_channel);
                $self->send_("426 Failure writing network stream.");
            }
        }
        else {
            $self->send_("425 Use PORT command first.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub NLST {
    my $self = shift;
    my $directory = shift;
    my $data_channel;
    my $ref;
    my %list;
    my $key;

    if ($self->{authenticated}) {
        if ($self->{active} && $self->{data_host} && $self->{data_port}) {
            $self->_read_vfs_changes;
            if (defined ($directory)) {
                chomp($directory);
            }
            $ref = $self->_vfs_list($directory);
            %list = %$ref;
            $self->send_("150 Here comes the directory listing.");
            eval {
                local $SIG{'ALRM'} = sub { die "TIMEOUT" };
                alarm($self->{timeout});
                $data_channel = $self->establish_data_channel;
                if ($data_channel) {
                    foreach $key (sort keys %list) {
                        print $data_channel "$key\r\n";
                    }
                    $self->slog_("send: <(DATA)>");
                    $self->close_data_channel($data_channel);
                    $self->send_("226 Directory send OK.");
                }
                else {
                    $self->send_("426 Failure writing network stream.");
                }
                alarm($self->{timeout});
            };
            alarm(0);
            if ($@ =~ /TIMEOUT/) {
                $self->close_data_channel($data_channel);
                $self->send_("426 Failure writing network stream.");
            }
        }
        else {
            $self->send_("425 Use PORT command first.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub PWD {
    my $self = shift;

    if ($self->{authenticated}) {
        if ($self->{current_dir}) {
            $self->send_("257 \"$self->{current_dir}\"");
        }
        else {
            $self->send_("257 \"/\"");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub CWD {
    my $self = shift;
    my $directory = shift;

    if ($self->{authenticated}) {
        chomp($directory);
        if (defined ($directory) && $directory) {
            $self->_read_vfs_changes;
            my $result = $self->_vfs_change_dir($directory);
            if ($result) {
                $self->send_("250 Directory successfully changed.");
            }
            else {
                $self->send_("550 Failed to change directory.");
            }
        }
        else {
            $self->send_("501 Syntax error in parameter.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub CDUP {
    my $self = shift;

    if ($self->{authenticated}) {
        $self->_read_vfs_changes;
        my $result = $self->_vfs_change_dir("..");
        if ($result) {
            $self->send_("250 Directory successfully changed.");
        }
        else {
            $self->send_("550 Failed to change directory.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub DELE {
    my $self = shift;
    my $file = shift;

    if ($self->{authenticated}) {
        chomp($file);
        if (defined ($file) && $file) {
            $self->_read_vfs_changes;
            my $result = $self->_vfs_del_file($file);
            if ($result) {
                $self->send_("250 Delete operation successful.");
                $self->{count_deleted}++;
                $self->_save_vfs_changes;
            }
            else {
                $self->send_("550 Delete operation failed.");
            }
        }
        else {
            $self->send_("501 Syntax error in parameter.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub RMD {
    my $self = shift;
    my $directory = shift;

    if ($self->{authenticated}) {
        chomp($directory);
        if (defined ($directory) && $directory ne "") {
            $self->_read_vfs_changes;
            my $result = $self->_vfs_del_dir($directory);
            if ($result) {
                $self->send_("250 Remove directory operation successful.");
                $self->{count_deleted}++;
                $self->_save_vfs_changes;
            }
            else {
                $self->send_("550 Remove directory operation failed.");
            }
        }
        else {
            $self->send_("501 Syntax error in parameter.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub MKD {
    my $self = shift;
    my $directory = shift;

    if ($self->{authenticated}) {
        chomp($directory);
        if (defined ($directory) && $directory ne "") {
            $self->_read_vfs_changes;
            my $result = $self->_vfs_add_dir($directory);
            if ($result) {
                $self->send_("257 \"$directory\" created");
                $self->slog_("info: Virtual directory '$result' created");
                $self->{count_created}++;
                $self->_save_vfs_changes;
            }
            else {
                $self->send_("550 Create directory operation failed.");
            }
        }
        else {
            $self->send_("501 Syntax error in parameter.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub TYPE {
    my $self = shift;
    my $type = shift;

    if ($self->{authenticated}) {
        chomp($type);
        if (defined ($type) && $type) {
            if ($type =~ /\AA(|\s(N|T|C))\z/i) {
                $self->{type} = "ASCII";
                if ($1) {
                    $self->{typeparam} = $1;
                }
                else {
                    $self->{typeparam} = "N";
                }
            }
            elsif ($type =~ /\AE(|\s(N|T|C))\z/i) {
                $self->{type} = "EBCDIC";
                if ($1) {
                    $self->{typeparam} = $1;
                }
                else {
                    $self->{typeparam} = "N";
                }
            }
            elsif ($type =~ /\AI\z/i || $type =~ /\AL\s8\z/i) {
                $self->{type} = "BINARY";
                $self->{typeparam} = "";
            }
            else {
                $self->send_("500 Unrecognised TYPE command.");
                return;
            }
            $self->send_("200 Switching to $self->{type} mode.");
        }
        else {
            $self->send_("500 Unrecognised TYPE command.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub STRU {
    my $self = shift;
    my $structure = shift;

    if ($self->{authenticated}) {
        chomp($structure);
        if (defined ($structure) && $structure) {
            if ($structure =~ /\AF\z/i) {
                $self->{stru} = "F";
            }
            elsif ($structure =~ /\AR\z/i) {
                $self->{stru} = "R";
            }
            elsif ($structure =~ /\AP\z/i) {
                $self->{stru} = "P";
            }
            else {
                $self->send_("504 Bad STRU command.");
                return;
            }
            $self->send_("200 Structure set to $self->{stru}.");
        }
        else {
            $self->send_("504 Bad STRU command.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub MODE {
    my $self = shift;
    my $mode = shift;

    if ($self->{authenticated}) {
        chomp($mode);
        if (defined ($mode) && $mode) {
            if ($mode =~ /\AS\z/i) {
                $self->{mode} = "S";
            }
            elsif ($mode =~ /\AB\z/i) {
                $self->{mode} = "B";
            }
            elsif ($mode =~ /\AC\z/i) {
                $self->{mode} = "C";
            }
            else {
                $self->send_("504 Bad MODE command.");
                return;
            }
            $self->send_("200 Mode set to $self->{mode}.");
        }
        else {
            $self->send_("504 Bad MODE command.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub NOOP {
    my $self = shift;

    if ($self->{authenticated}) {
        $self->send_("200 NOOP ok.");
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub STAT {
    my $self = shift;
    my $directory = shift;
    my $ref;
    my %list;
    my $key;

    if ($self->{authenticated}) {
        $self->_read_vfs_changes;
        if (defined ($directory)) {
            chomp($directory);
            $ref = $self->_vfs_list($directory);
            %list = %$ref;
            $self->send_("213-Status follows:");
            foreach $key (sort keys %list) {
                $self->send_("$list{$key}$key");
            }
            $self->send_("213 End of status");
        }
        else {
            $self->send_("211-FTP server status:");
            # begin content
            $self->send_("     Connected to $self->{server}->{sockaddr}");
            $self->send_("     Logged in as $self->{username}");
            $self->send_("     TYPE: $self->{type}");
            $self->send_("     Session timeout in seconds is $self->{timeout}");
            $self->send_("     Control connection is plain text");
            $self->send_("     Data connections will be plain text");
            $self->send_("     Maximum file size is $self->{max_filesize} bytes");
            $self->send_("     $self->{version}");
            # end content
            $self->send_("211 End of status");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub HELP {
    my $self = shift;
    my $option = shift;

    $self->send_("214-The following commands are recognized.");
    $self->send_(" ABOR CDUP CWD  DELE HELP LIST MKD  MODE");
    $self->send_(" NLST NOOP PASS PORT PWD  QUIT RETR RMD");
    $self->send_(" STAT STOR STRU SYST TYPE USER");
    $self->send_("214 Help OK.");
}


sub STOR {
    my $self = shift;
    my $file = shift;
    my $serviceName = $self->{servicename};
    my $dir;
    my $data_channel;
    my $storFileName;
    my $buf;
    my $data;
    my $bytes = 0;

    if ($self->{authenticated}) {
        if ($self->{active} && $self->{data_host} && $self->{data_port}) {
            chomp($file);
            if (defined ($file) && $file ne "") {
                $self->_read_vfs_changes;
                $dir = $self->_dirname($file);
                if ($self->_vfs_dir_exists($dir)) {
                    $self->send_("150 Ok to send data.");
                }
                else {
                    $self->send_("553 Could not create file.");
                    return;
                }
                eval {
                    local $SIG{'ALRM'} = sub { die "TIMEOUT" };
                    alarm($self->{timeout});
                    $data_channel = $self->establish_data_channel;
                    if ($data_channel) {
                        $self->slog_("recv: <(DATA)>");
                        while (read(\*$data_channel, $buf, 1024)) {
                            $data .= $buf;    
                            alarm($self->{timeout});
                            last if (length($data) > $self->{max_filesize});
                        }
                        $self->close_data_channel($data_channel);
                        $bytes = length($data);

                        # write data received to file
                        if ($bytes <= $self->{max_filesize}) {
                            my $filehash = Digest::SHA->new(256);
                            $filehash->add($data);
                            $storFileName = $self->{upload_dir} . "/" . $filehash->hexdigest;
                            my $STORFILE;

                            if (-e $storFileName) {
                                $self->slog_("info: Upload file $storFileName already exists");
                            }
                            elsif (! open ($STORFILE, "> $storFileName")) {
                                INetSim::Log::MainLog("Error: Unable to create FTP STOR data file '$storFileName'", $self->{servicename});
                            }
                            else {
                                binmode $STORFILE;
                                chmod 0660, $storFileName;
                                print $STORFILE $data;
                                close $STORFILE;
                                $self->slog_("info: Stored $bytes bytes of data to: $storFileName");
                            }
                            my $result = $self->_vfs_add_file($file, $storFileName);
                            if ($result) {
                                 $self->slog_("info: original file name: $file, full virtual path: $result");
                                 $self->_save_vfs_changes;
                            }
                            else {
                                $self->slog_("info: original file name: $file, full virtual path: error-not-saved");
                            }
                            $self->send_("226 File receive OK.");
                            $self->{count_created}++;
                        }
                        else {
                            $self->send_("552 Maximum file size of $self->{max_filesize} bytes exceeded.");
                        }
                    }
                    else {
                        $self->send_("426 Failure writing network stream.");
                    }
                };
                alarm(0);
                if ($@ =~ /TIMEOUT/) {
                    $self->close_data_channel($data_channel);
                    $self->send_("426 Failure writing network stream.");
                }
            }
            else {
                $self->send_("501 Syntax error in parameter.");
            }
        }
        else {
            $self->send_("425 Use PORT command first.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub RETR {
    my $self = shift;
    my $file = shift;
    my $data_channel;
    my $buf;
    my $data;
    my $bytes = 0;

    if ($self->{authenticated}) {
        if ($self->{active} && $self->{data_host} && $self->{data_port}) {
            chomp($file);
            if (defined ($file) && $file ne "") {
                $self->_read_vfs_changes;
                my $vfile = $self->_vfs_file_exists($file);
                if ($vfile) {
                    my ($perm, $usergroup, $size, $mtime, $type, $rpath) = split (/\|/, $VFS{"$vfile"});
                    if (defined ($type) && $type eq "file" && defined ($rpath) && -f $rpath && -r $rpath) {
                        if (open (my $DAT, "$rpath")) {
                            binmode $DAT;
                            while (read($DAT, $buf, 1024)) {
                                $data .= $buf;
                                alarm($self->{timeout});
                            }
                            close $DAT;
                        }
                    }
                    elsif (defined ($type) && $type eq "string" && defined ($rpath) && $rpath ne "") {
                        $data = $rpath;
                    }
                    $size = length($data);
                    if (defined ($data) && $data ne "") {
                        $self->send_("150 Opening BINARY mode data connection for $file ($size bytes).");
                        eval {
                            local $SIG{'ALRM'} = sub { die "TIMEOUT" };
                            alarm($self->{timeout});
                            $data_channel = $self->establish_data_channel;
                            if ($data_channel) {
                                $self->slog_("send: <(DATA)>");
                                print $data_channel $data;
                                alarm($self->{timeout});
                                if ($type eq "file") {
                                    $self->slog_("info: Sending file: $rpath");
                                }
                                else {
                                    $self->slog_("info: Sending file: <string>");
                                }
                                $self->close_data_channel($data_channel);
                                $self->send_("226 File send OK.");
                                $self->{count_retrieved}++;
                            }
                            else {
                                $self->send_("426 Failure writing network stream.");
                            }
                            alarm($self->{timeout});
                        };
                        alarm(0);
                        if ($@ =~ /TIMEOUT/) {
                            $self->close_data_channel($data_channel);
                            $self->send_("426 Failure writing network stream.");
                        }
                    }
                    else {
                        $self->send_("550 Failed to open file.");
                    }
                }
                else {
                    $self->send_("550 Failed to open file.");
                }
            }
            else {
                $self->send_("501 Syntax error in parameter.");
            }
        }
        else {
            $self->send_("425 Use PORT command first.");
        }
    }
    else {
        $self->send_("530 Please login with USER and PASS.");
    }
}


sub establish_data_channel {
    my $self = shift;

    if ($self->{active} && $self->{data_host} && $self->{data_port}) {
        my $handle = IO::Socket::INET->new(Proto => "tcp", PeerAddr  => $self->{data_host}, PeerPort  => $self->{data_port}, Type => SOCK_STREAM, Reuse => 1);
        if (defined ($handle)) {
            $handle->autoflush(1);
            if ($self->{ssl_enabled} && ! $self->upgrade_to_ssl($handle)) {
                $self->slog_("info: Error setting up SSL:  $self->{last_ssl_error}");
            }
            else {
                $self->slog_("info: Data connection to $self->{data_host}:$self->{data_port} established.");
                return \*$handle;
            }
        }
        $self->{active} = 0;
        $self->{data_host} = "";
        $self->{data_port} = "";
    }
    return undef;
}


sub close_data_channel {
    my $self = shift;
    my $handle = shift;

    if (defined ($handle)) {
        $handle->close();
        $self->slog_("info: Data connection to $self->{data_host}:$self->{data_port} closed.");
        $self->{active} = 0;
        $self->{data_host} = "";
        $self->{data_port} = "";
    }
}


### BEGIN: VFS stuff


sub init_VFS {
    my $self = shift;
    my @dirs;
    my $name;
    my $vname;
    my $mtime;
    my $dir;

    # read the session file, if exist
    $self->_read_vfs_changes;

#    # rebuild only if empty
#    return if (keys (%VFS) >= 1);

    # first, add '/' to the filesystem
    $mtime = int (INetSim::FakeTime::get_faketime() - rand(7200));
    $VFS{'/'} = "drwxrwxrwx|0|4096|$mtime||";
    $self->{current_dir} = "/";
    # now walk through the document root and add directories and files
    push (@dirs, $self->{document_root});        # push document root to the "stack"
    while (@dirs) {
        $dir = pop (@dirs);
        my $DIRHANDLE;

        if (opendir ($DIRHANDLE, $dir)) {
            while (defined ($name = readdir ($DIRHANDLE))) {
                next if $name eq '.';
                next if $name eq '..';
                $vname = "$dir/$name";
                $vname =~ s/\A$self->{document_root}//;        # chr00t ;-)
                $mtime = int (INetSim::FakeTime::get_faketime() - rand(3600));
                if (-d "$dir/$name") {
                    push (@dirs, "$dir/$name");
                    $self->_vfs_add_dir($vname, "$dir/$name", $mtime);
                }
                elsif (-f "$dir/$name") {
                    $self->_vfs_add_file($vname, "$dir/$name", $mtime);
                }
            }
            closedir $DIRHANDLE;
        }
    }
}


sub _vfs_add_file {
    my $self = shift;
    my $vpath = shift;        # virtual path
    my $rpath = shift;        # real path
    my $mtime = shift || INetSim::FakeTime::get_faketime();
    my $usergroup = int (1000 + rand(100));
    my $size;
    my $dir;

    if (defined ($vpath) && defined ($rpath)) {
        if (-f $rpath && -r $rpath) {
            # add base directory of the file
            $self->_vfs_add_dir($self->_dirname($vpath));
            # get the real file size
            $size = -s $rpath;
            # check for absolute path
            if ($vpath !~ /\A\//) {
                # build absolute virtual path name
                $vpath = "$self->{current_dir}/$vpath";
            }
            # filter virtual path name
            $vpath = $self->_filter_pathstring($vpath);
            # add file to vfs (if not empty)
            if (defined ($vpath) && $vpath ne "" && $vpath ne "/") {
                $VFS{"$vpath"} = "-rw-rw-rw-|$usergroup|$size|$mtime|file|$rpath";
                return ($vpath);
            }
        }
    }
    return undef;
}


sub _vfs_del_file {
    my $self = shift;
    my $vpath = shift;        # virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} !~ /\Ad/) {
            delete $VFS{"$vpath"};
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_file_exists {
    my $self = shift;
    my $vpath = shift;        # virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} !~ /\Ad/) {
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_add_dir {
    my $self = shift;
    my $vpath = shift;        # virtual path
    my $rpath = shift || "";        # real path not needed
    my $mtime = shift || INetSim::FakeTime::get_faketime();
    my $usergroup = int (1000 + rand(100));
    my $size = 4096;

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        # add directory to vfs (if not empty)
        if (defined ($vpath) && $vpath ne "" && $vpath ne "/") {
            $VFS{"$vpath"} = "drw-rw-rw-|$usergroup|$size|$mtime||";
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_del_dir {
    my $self = shift;
    my $vpath = shift;        # virtual path
    my $key;

    if (defined ($vpath) && $vpath ne "" && $vpath ne "/") {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && $vpath ne "/" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} =~ /\Ad/) {
            # we can't delete the current working directory ! ;-)
            return undef if ($self->{current_dir} =~ /\A$vpath(\/.*?)?\z/);
            foreach $key (keys %VFS) {
                next if ($key eq $vpath);
                if ($self->_dirname($key) eq $vpath) {
                    # return if directory is not empty and recursive_delete is not allowed
                    return undef if (! $self->{recursive_delete});
                    delete $VFS{"$key"};
                }
            }
            delete $VFS{"$vpath"};
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_change_dir {
    my $self = shift;
    my $vpath = shift;        # virtual path

    if (defined ($vpath) && $vpath ne "") {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        # check if directory exist
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} =~ /\Ad/) {
            $self->{current_dir} = $vpath;
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_dir_exists {
    my $self = shift;
    my $vpath = shift;        # virtual path

    if (defined ($vpath)) {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
        # filter virtual path name
        $vpath = $self->_filter_pathstring($vpath);
        if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} =~ /\Ad/) {
            return ($vpath);
        }
    }
    return undef;
}


sub _vfs_list {
    my $self = shift;
    my $vpath = shift;        # virtual path
    my $key;
    my $dir;
    my $name;
    my %content;
    my $line;

    if (! defined ($vpath)) {
        $vpath = "$self->{current_dir}/";
    }
    elsif (defined ($vpath) && $vpath ne "") {
        # check for absolute path
        if ($vpath !~ /\A\//) {
            # build absolute virtual path name
            $vpath = "$self->{current_dir}/$vpath";
        }
    }
    # filter virtual path name
    $vpath = $self->_filter_pathstring($vpath);
    if (defined ($vpath) && $vpath ne "" && defined ($VFS{"$vpath"}) && $VFS{"$vpath"} =~ /\Ad/) {
        foreach $key (keys %VFS) {
            next if ($key eq $vpath);
            if ($self->_dirname($key) eq $vpath) {
                $name = $self->_basename($key);
                my ($perm, $usergroup, $size, $mtime) = split(/\|/, $VFS{"$key"});
                if (defined ($perm) && defined ($usergroup) && defined ($size) && defined ($mtime)) {
                    if ($perm =~ /\Ad/) {
                        $line = sprintf("%10s %4s %5s %5s %13s %12s ", $perm, "2", $usergroup, $usergroup, $size, $self->_format_mtime($mtime));
                    }
                    else {
                        $line = sprintf("%10s %4s %5s %5s %13s %12s ", $perm, "1", $usergroup, $usergroup, $size, $self->_format_mtime($mtime));
                    }
                    $content{"$name"} = $line;
                }
            }
        }
    }
    return (\%content);
}


sub _read_vfs_changes {
    my $self = shift;
    my %seen = ();
    my @raw;
    my $key;

    if (open (my $SES, "$self->{sessionfile}")) {
        chomp(@raw = <$SES>);
        close $SES;
        foreach (grep { ! $seen{ $_ }++ } @raw) {
            my ($content, $vpath) = split (/\!/, $_, 2);
            chomp($vpath);
            $VFS{"$vpath"} = $content;
        }
    }
    return undef;
}


sub _save_vfs_changes {
    my $self = shift;
    my %seen = ();
    my @raw;
    my $key;

    while () {
        if (open (my $SES, "> $self->{sessionfile}")) {
            chmod 0660, $self->{sessionfile};
            if (flock($SES, LOCK_EX)) {
                foreach $key (keys %VFS) {
                    print $SES "$VFS{$key}!$key\n";
                }
                close $SES;
                return 1;
            }
            close $SES;
        }
        sleep 1;
    }
    return undef;
}


sub _filter_pathstring {
    my $self = shift;
    my $path = shift;
    my @parts;

    if (defined ($path) && $path ne "") {
        @parts = split(/\/+/, $path);
        @parts = ('', '') unless @parts;
        unshift (@parts, '') unless @parts > 1;
        for (my $i = 1; $i < @parts;) {
            if ($parts[$i] eq '.') {
                splice (@parts, $i, 1);
            }
            elsif ($parts[$i] eq '..' && $i == 1) {
                splice (@parts, $i, 1);
            }
            elsif ($parts[$i] eq '..') {
                splice (@parts, ($i - 1), 2);
                $i--;
            }
            else {
                $i++;
            }
        }
        unshift (@parts, '') unless @parts > 1;
        return (join ('/', @parts));
    }
    return undef;
}


sub _basename {
    my $self = shift;
    my $path = shift;
    my @parts;

    if (defined ($path) && $path ne "") {
        if ($path eq '/') {
            return '/';
        } else {
            @parts = split (m{/}, $path);
            return (pop @parts);
        }
    }
    return undef;
}


sub _dirname {
    my $self = shift;
    my $path = shift;

    if (defined ($path) && $path ne "") {
        if ($path eq '/') {
                return '/';
        } else {
                my @parts = split (m{/}, $path);
                pop @parts;
                push (@parts, '') if @parts == 1;
                return (join ('/', @parts));
        }
    }
    return undef;
}


sub _format_mtime {
    my $self = shift;
    my $mtime = shift || INetSim::FakeTime::get_faketime();
    my @months = qw/Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec/;
    my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) = localtime($mtime);

    return (sprintf("%3s %02d %02d:%02d", $months[$mon], $mday, $hour, $min));
}


sub upgrade_to_ssl {
    my $self = shift;
    my $socket = shift || $self->{server}->{client};
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

    my $result = IO::Socket::SSL::socket_to_SSL( $socket, %ssl_params );

    if (defined $result) {
        $self->{tls_cipher} = lc($result->get_cipher());
        return 1;
    }
    else {
        $self->{last_ssl_error} = IO::Socket::SSL::errstr();
        return 0;
    }
}


sub error_exit {
    my $self = shift;
    my $msg = shift;
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
