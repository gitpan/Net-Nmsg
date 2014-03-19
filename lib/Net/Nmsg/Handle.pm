# Copyright (C) 2010-2013 by Carnegie Mellon University
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, as published by
# the Free Software Foundation, under the terms pursuant to Version 2,
# June 1991.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.

package Net::Nmsg::Handle;

use strict;
use warnings;
use Carp;

use Net::Nmsg::Util qw( :io :sniff );

use IO::File;
use IO::Socket::INET;

use constant FILE_IO        => 'IO::File';
use constant SOCKET_IPV4_IO => 'IO::Socket::INET';
use constant SOCKET_IPV6_IO => 'IO::Socket::INET6';
use constant PCAP_IO        => 'Net::Nmsg::IO::Pcap';
use constant CALLBACK_IO    => 'Net::Nmsg::IO::Callback';

###

sub open_input_file  { shift->_open_file(r => @_) }
sub open_output_file { shift->_open_file(w => @_) }

sub _open_file {
  my $class = shift;
  my($mode, $spec) = @_;
  $mode ||= 'r';
  my $fh = $class->FILE_IO->new;
  if (defined (my $fd = fileno($spec))) {
    $fh->fdopen($fd, $mode) || die $!;
  }
  else {
    $fh->open($spec, $mode) || die $!;
  }
  $fh;
}

###

sub _sock_spec_to_opt {
  my $class = shift;
  return unless @_;
  my($host, $port);
  if (@_ % 2) {
    ($host, $port) = parse_socket_spec(shift);
  }
  else {
    ($host, $port) = splice(@_, 0, 2);
  }
  return($host, $port, @_);
}

sub _make_sock {
  my $class = shift;
  return unless @_;
  my %opt = @_;
  my $s = $class->SOCKET_IPV4_IO->new(%opt);
  if (!$s) {
    die "Problem creating socket: $!\n" unless $! =~ /invalid\s+arg/i;
    my $msg = $!;
    my $ipv6_class = $class->SOCKET_IPV6_IO;
    eval "use $ipv6_class";
    die "No fallback from \"$msg\" : $@" if $@;
    $s = $ipv6_class->new(%opt) or die "Problem creating socket: $!\n";
  }
  $s;
}

sub open_input_sock {
  my $class = shift;
  die "spec required" unless @_;
  my $spec = shift;
  if (! is_socket($spec)) {
    my($host, $port, %opt) = $class->_sock_spec_to_opt($spec, @_);
    my %sopt = (
      LocalAddr => $host,
      LocalPort => $port,
      Proto     => 'udp',
      Type      => SOCK_DGRAM,
      ReuseAddr => 1,
      ReusePort => 1,
    );
    eval { $spec = $class->_make_sock(%sopt) };
    if ($@) {
      #print STDERR "TRY AGAIN minus ReusePort\n";
      delete $sopt{ReusePort};
      $spec = $class->_make_sock(%sopt);
    }
    #print STDERR "SOCK RESULT: ", $spec || 'undef', "\n";
    $spec || return;
    my $rcvbuf = delete $opt{rcvbuf} || NMSG_DEFAULT_SO_RCVBUF;
    eval { $spec->sockopt(SO_RCVBUF => $rcvbuf) };
  }
  #print STDERR "open_input_sock() returns $spec\n";
  $spec;
}

sub open_output_sock {
  my $class = shift;
  die "spec required" unless @_;
  my $spec = shift;
  if (! is_socket($spec)) {
    my($host, $port, %opt) = $class->_sock_spec_to_opt($spec, @_);
    my %sopt = (
      PeerAddr  => $host,
      PeerPort  => $port,
      Proto     => 'udp',
      Type      => SOCK_DGRAM,
      Broadcast => $opt{broadcast} ? 1 : 0,
    );
    $spec = $class->_make_sock(%sopt) || return;
    my $sndbuf = delete $opt{sndbuf} || NMSG_DEFAULT_SO_SNDBUF;
    eval { $spec->sockopt(SO_SNDBUF => $sndbuf) };
  }
  $spec;
}

###

sub open_input_pcap_file {
  my $class = shift;
  my($spec, %opt) = @_;
  $class->PCAP_IO->open_file($spec, bpf => $opt{bpf});
}

sub open_input_pcap_iface {
  my $class = shift;
  my($spec, %opt) = @_;
  $class->PCAP_IO->open_iface(
    $spec,
    bpf     => $opt{bpf},
    snaplen => $opt{snaplen},
    promisc => $opt{promisc},
  );
}

###

sub open_output_cb { shift->CALLBACK_IO->open(shift) }

######## IO::Handle mockups

package Net::Nmsg::IO::Pcap;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Layer );

use Net::Nmsg::Util qw( :io );

use constant NMSG_PCAP_XS => 'Net::Nmsg::XS::nmsg_pcap';
use constant PCAP_XS      => 'Net::Nmsg::XS::pcap';

my %Defaults = (
  snaplen => NMSG_DEFAULT_SNAPLEN,
  promisc => 0,
  bpf     => undef,
);

sub _defaults { \%Defaults }

sub get_bpf     { shift->_get_xs_opt('bpf'    ) }
sub get_snaplen { shift->_get_io_opt('snaplen') }
sub get_promisc { shift->_get_io_opt('promisc') }

sub set_bpf     { shift->_set_xs_opt(bpf     => @_) }
sub set_snaplen { shift->_set_io_opt(snaplen => @_) }
sub set_promisc { shift->_set_io_opt(promisc => @_) }

sub open {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (is_file($spec)) {
    $self->open_file($spec, %opt) || ($fatal ? croak $self->error : return);
  }
  elsif (is_interface($spec)) {
    $self->open_iface($spec, %opt) || ($fatal ? croak $self->error : return);
  }
  else {
    $self->error("not a file or interface (got root?)");
    return unless $fatal;
    croak $self->error;
  }
  $self;
}

sub open_file {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  my $pcap;
  eval { $pcap = $self->PCAP_XS->open_offline($spec) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  eval { return $self->_open_pcap_handle($pcap, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self;
}

sub open_iface {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  my $snaplen = defined $opt{snaplen} ? $opt{snaplen} : NMSG_DEFAULT_SNAPLEN;
  my $promisc = defined $opt{promisc} ? $opt{promisc} : NMSG_DEFAULT_PROMISC;
  my $pcap;
  eval { $pcap = $self->PCAP_XS->open_live($spec, $snaplen, $promisc) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  eval { $self->_open_pcap_handle($pcap, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self;
}

sub _open_pcap_handle {
  my $self = shift;
  my $pcap = shift || die "pcap handle required";
  my $nmsg_pcap;
  eval { $nmsg_pcap = $self->NMSG_PCAP_XS->open_input($pcap) }; 
  $@ && croak $@;
  *$self->{_io} = $pcap;
  *$self->{_xs} = $nmsg_pcap;
  $self->_init_opts(@_);
  $self->_dup_io_r($self->fileno);
  $self;
}

### IO layer

sub blocking { }

sub eof { }

sub is_live { (shift->_xs || return)->get_type == NMSG_PCAP_TYPE_LIVE }

sub error {
  my $self = shift;
  *$self->{error} = shift if @_;
  return *$self->{error} if defined *$self->{error};
  ($self->_io || return)->get_error;
}

sub opened {
  my $self = shift;
  $self->is_live || defined($self->fileno);
}

sub fileno {
  my $self = shift;
  $self->is_live
    ? ($self->_io || return)->get_selectable_fd
    : ($self->_io || return)->fileno;
}

sub stat {
  my $self = shift;
  $self->is_live
    ? $self->_fake_stat
    : stat ($self->_io || return)->fileno;
}

########

package Net::Nmsg::IO::Callback;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Layer );

sub open {
  my($self, $cb, $fatal, %opt) = shift->_open_init(@_);
  if (! ref $cb || ref $cb ne 'CODE') {
    $self->error("not a CODE reference");
    $fatal ? croak $self->error : return;
  }
  *$self->{count} = 0;
  *$self = $cb;
  $self;
}

sub close {
  my $self = shift;
  undef(&{*$self});
  $self->SUPER::close;
}

sub opened { defined *{shift()}->{count} }

sub write { *{shift()}->(@_) }

sub getpos { *{shift()}->{count} }

*tell = \&getpos;

sub stat { shift->_fake_stat }

1;
