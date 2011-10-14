# Copyright (C) 2010-2011 by Carnegie Mellon University
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

package Net::Nmsg::Input;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Layer );

use overload
  '<>'     => \&read,
  fallback => 1;

use Net::Nmsg::Util qw( :io :vendor :result );
use Net::Nmsg::Msg;
use Net::Nmsg::Handle;

use constant HANDLE_IO => 'Net::Nmsg::Handle';
use constant INPUT_XS  => 'Net::Nmsg::XS::input';

my %Defaults = (

  # nmsg
  filter_vendor   => undef,
  filter_msgtype  => undef,
  filter_source   => undef,
  filter_operator => undef,
  filter_group    => undef,
  blocking_io     => 1,

  # pcap
  bpf      => undef,
  snaplen  => NMSG_DEFAULT_SNAPLEN,
  promisc  => 0,

);

sub _defaults { \%Defaults }

sub get_filter_msgtype  { shift->_get_xs_opt(filter_msgtype  => @_) }
sub get_filter_operator { shift->_get_xs_opt(filter_operator => @_) }
sub get_filter_source   { shift->_get_xs_opt(filter_source   => @_) }
sub get_filter_group    { shift->_get_xs_opt(filter_group    => @_) }
sub get_blocking_io     { shift->_get_xs_opt(blocking_io     => @_) }

sub set_filter_msgtype  { shift->_set_xs_opt(filter_msgtype  => @_) }
sub set_filter_operator { shift->_set_xs_opt(filter_operator => @_) }
sub set_filter_source   { shift->_set_xs_opt(filter_source   => @_) }
sub set_filter_group    { shift->_set_xs_opt(filter_group    => @_) }
sub set_blocking_io     { shift->_set_xs_opt(blocking_io     => @_) }

sub get_snaplen { shift->_get_io_opt(snaplen => @_) }
sub get_promisc { shift->_get_io_opt(promisc => @_) }
sub get_bpf     { shift->_get_io_opt(bpf     => @_) }

sub set_snaplen { shift->_set_io_opt(snaplen => @_) }
sub set_promisc { shift->_set_io_opt(promisc => @_) }
sub set_bpf     { shift->_set_io_opt(bpf     => @_) }

###

sub is_file  { (shift->_xs || return)->is_file  }
sub is_sock  { (shift->_xs || return)->is_sock  }
sub is_pres  { (shift->_xs || return)->is_pres  }
sub is_pcap  { (shift->_xs || return)->is_pcap  }
sub is_iface { (shift->_xs || return)->is_iface }

###

sub _map_opts {
  my $self = shift;
  my %opt  = @_;
  my $vendor  = delete $opt{filter_vendor};
  my $msgtype = delete $opt{filter_msgtype};
  return %opt unless defined $vendor || defined $msgtype;
  $opt{filter_msgtype} = [$vendor, $msgtype];
  %opt;
}

sub _init_input {
  my $self = shift;
  my($spec, $io, $xs, %opt) = @_;
  *$self->{_spec} = $spec;
  *$self->{_io}   = $io;
  *$self->{_xs}   = $xs;
  $self->_dup_io_r;
  $self->_init_opts(%opt);
  $self;
}

sub open {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (Net::Nmsg::Util::looks_like_socket($spec)) {
    #print STDERR "SOCKET $self\n";
    return $self->open_sock($spec, %opt)
      || ($fatal ? croak $self->error : return);
  }
  elsif (Net::Nmsg::Util::is_file($spec) || ($spec || '') =~ /\.\w+$/) {
    #print STDERR "FILE $self\n";
    if (($spec || '') =~ /\.w+$/ && ! -f $spec) {
      $fatal ? croak("file does not exist " . $spec) : return;
    }
    if (Net::Nmsg::Util::is_nmsg_file($spec) ||
        ($spec || '') =~ /\.nmsg$/) {
      #print STDERR "NMSG $self\n";
      return $self->open_file($spec, %opt)
        || ($fatal ? croak $self->error : return);
    }
    elsif (Net::Nmsg::Util::is_pcap_file($spec) ||
           ($spec || '') =~ /\.pcap$/) {
      #print STDERR "PCAP $self\n";
      return $self->open_pcap($spec, %opt)
        || ($fatal ? croak $self->error : return);
    }
    else {
      #print STDERR "PRES $self\n";
      return $self->open_pres($spec, %opt)
        || ($fatal ? croak $self->error : return);
    }
  }
  elsif (Net::Nmsg::Util::is_interface($spec)) {
    #print STDERR "IFACE $self\n";
    return $self->open_iface($spec, %opt)
      || ($fatal ? croak $self->error : return);
  }
  else {
    #print STDERR "OOPS UNKNOWN $spec\n";
    $self->error("not sure what to do with spec $spec");
    croak $self->error if $fatal;
  }
  $self;
}

sub open_file {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  my $io;
  eval { $io = $self->HANDLE_IO->open_input_file($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  my $xs;
  eval { $xs = $self->INPUT_XS->open_file($io) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  $self->_init_input($spec, $io, $xs, %opt);
}

sub open_sock {
  my $self = shift;
  my $spec = @_ % 2 ? shift : join('/', splice(@_, 0, 2));
  ($self, $spec, my($fatal, %opt)) = $self->_open_init($spec, @_);
  if (! defined $spec) {
    $self->error("spec required");
    return unless $fatal;
    croak $self->error;
  }
  my $io;
  $io = $self->HANDLE_IO->open_input_sock($spec, %opt);
  my $xs = $self->INPUT_XS->open_sock($io);
  $self->_init_input($spec, $io, $xs, %opt);
  $self;
}

sub open_pres {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (! $opt{filter_msgtype}) {
    $self->error("filter_vendor and filter_msgtype required");
    return unless $fatal;
    croak $self->error;
  }
  my $io;
  eval { $io = $self->HANDLE_IO->open_input_file($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  my $xs;
  eval { $xs = $self->INPUT_XS->open_pres($io, @{$opt{filter_msgtype}}) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  $self->_init_input($spec, $io, $xs, %opt);
}

sub open_pcap {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (! $opt{filter_msgtype}) {
    $self->error("filter_vendor and filter_msgtype required");
    return unless $fatal;
    croak $self->error;
  }
  my $io;
  eval { $io = $self->HANDLE_IO->open_input_pcap_file($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  my $xs;
  eval { $xs = $self->INPUT_XS->open_pcap($io->_xs, @{$opt{filter_msgtype}}) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  $self->_init_input($spec, $io, $xs, %opt);
}

sub open_iface {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (! $opt{filter_msgtype}) {
    $self->error("vendor and msgtype required");
    return unless $fatal;
    croak $self->error;
  }
  my $io;
  eval { $io = $self->HANDLE_IO->open_input_pcap_iface($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  my $xs;
  eval { $xs = $self->INPUT_XS->open_pcap($io->_xs, @{$opt{filter_msgtype}}) };
  $@ && $self->error($@) && ($fatal ? croak $@ : return);
  $self->_init_input($spec, $io, $xs, %opt);
}

### nmsg input

sub loop {
  my $self = shift;
  my $res  = $self->_xs->loop(shift, shift || -1);
  $self->eof(1) if $res == NMSG_RES_EOF;
  $self;
}

### perl IO

sub blocking {
  my $self = shift;
  @_ ? $self->set_blocking_io(shift) : $self->get_blocking_io;
}

sub eof {
  my $self = shift;
  @_ ? $self->_set_opt(_eof => shift) : $self->_get_opt('_eof');
}

sub read {
  my $self = shift;
  my $xs = $self->_xs || return;
  my $msg = $xs->read($self->get_blocking_io);
  return($_ = $msg) if $msg;
  $self->eof(1);
  return;
}

###

1;

__END__

=head1 NAME

Net::Nmsg::Input - Perl interface for nmsg inputs

=head1 SYNOPSIS

  use Net::Nmsg::Input;
  use Net::Nmsg::Output;

  my $in  = Net::Nmsg::Input->open('input.nmsg');
  my $out = Net::Nmsg::Output->open('output.nmsg');

  my $c = 0;

  while (my $msg = $in->read) {
    print "got message $c $msg\n";
    $out->write($msg);
  }

  # alternatively:

  my $cb = sub {
    print "got message $c ", shift, "\n"
    $out->write($msg);
  };
  $in->loop($cb);

=head1 DESCRIPTION

Net::Nmsg::Input is the base class of a set format-specific input
classes which provide perl interfaces for the Net::Nmsg::XS::input
extension.

=head1 CONSTRUCTORS

=over 4

=item open(%options)

Creates a new input object. The class of the returned object depends on
the apparent format of the input. The resulting object can be treated
like an IO handle. The following both work:

  while (my $msg = <$in>) {
    # deal with $msg
  }

  while (my $msg = $in->read()) {
    # deal with $msg
  }

Available options:

=over 4

=item filter_vendor

=item filter_msgtype

Filter incoming messages based on the given vendor/msgtype. Both are
required if filtering is desired. Values can either be by name or
numeric id.

=item filter_source

Filter incoming messages based on the given source (nmsg only).

=item filter_operator

Filter incoming messages based on the given operator (nmsg only).

=item filter_group

Filter incoming messages based on the given group (nmsg only).

=item blocking_io

Specify whether or not this input is blocking or not.

=item bpf

Specify a Berkley Packet Filter (pcap file/interface only)

=item snaplen

Packet capture size (live interface only)

=item promisc

Promiscuous mode (live interface only)

=back

=item open_nmsg($spec, %options)

Opens an input in nmsg format, as specified by file name, file handle,
socket specification, or socket handle.

=item open_pres($spec, %options)

Opens an input in presentation format, as specified by file name or file
handle. The 'filter_vendor' and 'filter_msgtype' options are required.

=item open_pcap($spec, %options)

Opens an input in pcap format, as specified by file name. The
'filter_vendor' and 'filter_msgtype' options are required.

=item open_iface($spec, %options)

Opens an input in pcap format, as specified by interface name The
'filter_vendor' and 'filter_msgtype' options are required.

=back

=head2 ACCESSORS

=over

=item set_msgtype($vendor, $msgtype)

=item get_msgtype()

=item set_filter_source($source)

=item get_filter_source()

=item set_filter_operator($operator)

=item get_filter_operator()

=item set_filter_group($group)

=item get_filter_group()

=item set_blocking_io($bool)

=item get_blocking_io()

=item set_bpf($bpf)

=item get_bpf()

=item set_snaplen($len)

=item get_snaplen()

=item set_promisc($bool)

=item get_promisc()

=back

=head2 METHODS

=over 4

=item read()

Returns the next message from this input, if available, as a
Net::Nmsg::Msg object.

=item loop($callback, [$count])

Initiate processing of this input source, passing messages to the given
code reference. Callbacks receive a single Net::Nmsg::Msg reference as
an argument. An optional parameter I<count> stops the loop after that
many messages have been returned via the callback.

=back

=head1 SEE ALSO

L<Net::Nmsg::IO>, L<Net::Nmsg::Output>, L<Net::Nmsg::Msg>, L<nmsgtool(1)>

=head1 AUTHOR

Matthew Sisk, E<lt>sisk@cert.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010-2011 by Carnegie Mellon University

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, as published by
the Free Software Foundation, under the terms pursuant to Version 2,
June 1991.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

=cut
