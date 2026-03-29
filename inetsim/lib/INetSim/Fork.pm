# -*- perl -*-
#
# INetSim::Fork - base class for INetSim::GenericServer
#
# This module is a slightly modified version of Net::Server::Fork
# for use with INetSim
#
# Net::Server::Fork is part of the Net::Server Perl library
# available from <http://search.cpan.org/~rhandom/Net-Server/>,
# see below for copyright notice.
#
# Modifications to this module for use with INetSim were made
# by Thomas Hungenberg & Matthias Eckert
#
################################################################
#
#  Net::Server::Fork - Net::Server personality
#
#  $Id: Fork.pm,v 1.22 2007/02/03 05:41:29 rhandom Exp $
#
#  Copyright (C) 2001-2007
#
#    Paul Seamons
#    paul@seamons.com
#    http://seamons.com/
#
#  This package may be distributed under the terms of either the
#  GNU General Public License
#    or the
#  Perl Artistic License
#
#  All rights reserved.
#
################################################################

package INetSim::Fork;

use base qw(Net::Server);
use strict;
use vars qw($VERSION);
use Net::Server::SIG qw(register_sig check_sigs);
use Socket qw(SO_TYPE SOL_SOCKET SOCK_DGRAM);
use POSIX qw(WNOHANG);

$VERSION = $Net::Server::VERSION; # done until separated

### override-able options for this package
sub options {
  my $self = shift;
  my $prop = $self->{server};
  my $ref  = shift;

  $self->SUPER::options($ref);

  foreach ( qw(max_servers max_dequeue
               check_for_dead check_for_dequeue) ){
    $prop->{$_} = undef unless exists $prop->{$_};
    $ref->{$_} = \$prop->{$_};
  }
}

### make sure some defaults are set
sub post_configure {
  my $self = shift;
  my $prop = $self->{server};

  ### let the parent do the rest
  $self->SUPER::post_configure;

  ### what are the max number of processes
  $prop->{max_servers} = 256
    unless defined $prop->{max_servers};

  ### how often to see if children are alive
  ### only used when max_servers is reached
  $prop->{check_for_dead} = 60
    unless defined $prop->{check_for_dead};

  ### I need to know who is the parent
  $prop->{ppid} = $$;

  ### let the post bind set up a select handle for us
  $prop->{multi_port} = 1;

}


### loop, fork, and process connections
sub loop {
  my $self = shift;
  my $prop = $self->{server};

  ### get ready for children
  $prop->{children} = {};
  if ($ENV{HUP_CHILDREN}) {
      my %children = map {/\A(\w+)\z/; $1} split(/\s+/, $ENV{HUP_CHILDREN});
      $children{$_} = {status => $children{$_}, hup => 1} foreach keys %children;
      $prop->{children} = \%children;
  }

  ### store number of children
  $prop->{numchilds} = 0;

  ### register some of the signals for safe handling
  register_sig(PIPE => 'IGNORE',
               INT  => sub { $self->server_close() },
               TERM => sub { $self->server_close() },
               QUIT => sub { $self->server_close() },
               HUP  => sub { $self->sig_hup() },
               CHLD => sub {
                 while ( defined(my $chld = waitpid(-1, WNOHANG)) ){
                   last unless $chld > 0;
                   $self->delete_child($chld);
                 }
               },
               );

  my ($last_checked_for_dead, $last_checked_for_dequeue) = (time(), time());

  ### this is the main loop
  while( 1 ){

    ### make sure we don't use too many processes
    my $n_children = grep { $_->{status} !~ /dequeue/ } (values %{ $prop->{children} });
    $prop->{numchilds} = scalar (keys %{ $prop->{children} });
    while ($n_children > $prop->{max_servers}){

      ### block for a moment (don't look too often)
      select(undef,undef,undef,5);
      check_sigs();

      ### periodically see which children are alive
      my $time = time();
      if( $time - $last_checked_for_dead > $prop->{check_for_dead} ){
        $last_checked_for_dead = $time;
        $self->log(2,"Max number of children reached ($prop->{max_servers}) -- checking for alive.");
        foreach (keys %{ $prop->{children} }){
          ### see if the child can be killed
          kill(0,$_) or $self->delete_child($_);
        }
      }
      $n_children = grep { $_->{status} !~ /dequeue/ } (values %{ $prop->{children} });
    }

    ### periodically check to see if we should clear a queue
    if( defined $prop->{check_for_dequeue} ){
      my $time = time();
      if( $time - $last_checked_for_dequeue
          > $prop->{check_for_dequeue} ){
        $last_checked_for_dequeue = $time;
        if( defined($prop->{max_dequeue}) ){
          my $n_dequeue = grep { $_->{status} =~ /dequeue/ } (values %{ $prop->{children} });
          if( $n_dequeue < $prop->{max_dequeue} ){
            $self->run_dequeue();
          }
        }
      }
    }

    $self->pre_accept_hook;

    ### try to call accept
    ### accept will check signals as appropriate
    if( ! $self->accept() ){
      last if $prop->{_HUP};
      last if $prop->{done};
      next;
    }

    $self->pre_fork_hook;

    ### fork a child so the parent can go back to listening
    my $pid = fork;

    ### trouble
    if( not defined $pid ){
      $self->log(1,"Bad fork [$!]");
      sleep(5);

    ### parent
    }elsif( $pid ){
      close($prop->{client}) if ! $prop->{udp_true};
      $prop->{children}->{$pid}->{status} = 'processing';

    ### child
    }else{
      ### the child will call post_accept_hook
      $self->run_client_connection;
      exit;

    }

  }

  ### fall back to the main run routine
}

sub pre_accept_hook {};

### Net::Server::Fork's own accept method which
### takes advantage of safe signals
sub accept {
  my $self = shift;
  my $prop = $self->{server};

  ### block on trying to get a handle (select created because we specified multi_port)
  my (@socks) = $prop->{select}->can_read(2);

  ### see if any sigs occured
  if( check_sigs() ){
    return undef if $prop->{_HUP};
    return undef unless @socks; # don't continue unless we have a connection
  }

  ### choose one at random (probably only one)
  my $sock = $socks[rand @socks];
  return undef unless defined $sock;

  ### check if this is UDP
  if( SOCK_DGRAM == $sock->getsockopt(SOL_SOCKET,SO_TYPE) ){
    $prop->{udp_true} = 1;
    $prop->{client}   = $sock;
    $prop->{udp_true} = 1;
    $prop->{udp_peer} = $sock->recv($prop->{udp_data},
                                    $sock->NS_recv_len,
                                    $sock->NS_recv_flags);

  ### Receive a SOCK_STREAM (TCP or UNIX) packet
  }else{
    delete $prop->{udp_true};
    $prop->{client} = $sock->accept();
    return undef unless defined $prop->{client};
  }
}

### override a little to restore sigs
sub run_client_connection {
  my $self = shift;

  ### close the main sock, we still have
  ### the client handle, this will allow us
  ### to HUP the parent at any time
  $_ = undef foreach @{ $self->{server}->{sock} };

  ### restore sigs (for the child)
  $SIG{HUP} = $SIG{CHLD}
     = $SIG{INT} = $SIG{TERM} = $SIG{QUIT} = 'DEFAULT';
  $SIG{PIPE} = 'IGNORE';

  delete $self->{server}->{children};

  $self->SUPER::run_client_connection;

}

### Stub function in case check_for_dequeue is used.
sub run_dequeue {
  die "run_dequeue: virtual method not defined";
}

sub close_children {
    my $self = shift;
    $self->SUPER::close_children(@_);

    check_sigs(); # since we have captured signals - make sure we handle them

    register_sig(PIPE => 'DEFAULT',
                 INT  => 'DEFAULT',
                 TERM => 'DEFAULT',
                 QUIT => 'DEFAULT',
                 HUP  => 'DEFAULT',
                 CHLD => 'DEFAULT',
                 );
}

sub pre_fork_hook {}


1;
#
