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

package Net::Nmsg::IO;

use strict;
use warnings;
use Carp;

use Symbol ();

use Data::Dumper;
$Data::Dumper::Indent = 1;

use Net::Nmsg::Util qw( :io :vendor :sniff :channel DEBUG );
use Net::Nmsg::Input;
use Net::Nmsg::Output;

use constant IO_INPUT  => 'Net::Nmsg::Input';
use constant IO_OUTPUT => 'Net::Nmsg::Output';
use constant IO_XS     => 'Net::Nmsg::XS::io';

my %Defaults = (
  debug    => DEBUG,
  mirrored => 0,
  count    => 0,
  interval => 0,

  operator       => undef,
  source         => undef,
  group          => undef,
  filter_vendor  => undef,
  filter_msgtype => undef,
);

###

sub _defaults { \%Defaults }

sub _opt       { *{shift()}->{_opt      } }
sub _inputs    { *{shift()}->{_inputs   } }
sub _outputs   { *{shift()}->{_outputs  } }
sub _callbacks { *{shift()}->{_callbacks} }

sub _xs {
  my $self = shift;
  *$self->{_xs} ||= $self->IO_XS->init();
}

sub inputs  { wantarray ? @{shift->_inputs } : [@{shift->_inputs }] }
sub outputs { wantarray ? @{shift->_outputs} : [@{shift->_outputs}] }

###

sub get_count    { shift->_opt->{count   } }
sub get_interval { shift->_opt->{interval} }
sub get_mirrored { shift->_opt->{mirrored} }
sub get_debug    { shift->_opt->{debug   } }

sub get_filter_operator { shift->_opt->{filter_operator} }
sub get_filter_source   { shift->_opt->{filter_source  } }
sub get_filter_group    { shift->_opt->{filter_group   } }

sub get_filter_msgtype {
  my $self = shift;
  return($self->_opt->{vendor}, $self->_opt->{msgtype});
}

sub set_count {
  my $self = shift;
  $self->_xs->set_count($self->_opt->{count} = shift);
}

sub set_interval {
  my $self = shift;
  $self->_xs->set_interval($self->_opt->{interval} = shift);
}

sub set_debug {
  my $self = shift;
  $self->_xs->set_debug($self->_opt->{debug} = shift);
}

sub set_mirrored {
  my $self = shift;
  my $v    = shift; 
  if ($v) {
    $self->_xs->set_output_mode(NMSG_OUTPUT_MODE_MIRROR);
  }
  else {
    $self->_xs->set_output_mode(NMSG_OUTPUT_MODE_STRIPE);
  }
  $self->_opt->{mirrored} = $v;
}

sub set_filter_operator {
  my $self = shift;
  $_->set_filter_operator(@_) foreach $self->inputs;
  $self->_opt->{filter_operator} = shift;
}

sub set_filter_source {
  my $self = shift;
  $_->set_filter_source(@_) foreach $self->inputs;
  $self->_opt->{filter_source} = shift;
}

sub set_filter_group {
  my $self = shift;
  $_->set_filter_group(@_) foreach $self->inputs;
  $self->_opt->{filter_group} = shift;
}

sub set_filter_msgtype {
  my $self = shift;
  my($vname, $mname) = msgtype_lookup(@_);
  $_->set_filter_msgtype($vname, $mname) foreach $self->inputs;
  $_->set_filter_msgtype($vname, $mname) foreach $self->outputs;
  $self->_opt->{vendor}  = $vname;
  $self->_opt->{msgtype} = $mname;
  return($vname, $mname);
}

### construction/opening

sub _init {
  my $self = shift;
  *$self->{_xs}        = undef;
  *$self->{_opt}       = {};
  *$self->{_inputs}    = [];
  *$self->{_outputs}   = [];
  *$self->{_callbacks} = {};
  $self;
}

sub new {
  my $class = shift;
  my $self = Symbol::gensym();
  bless $self, $class;
  $self->_init;
  my %opt = @_;
  my $defaults = $self->_defaults;
  for my $o (keys %opt) {
    if (! exists $defaults->{$o} && $o !~ /^_/) {
      croak "uknown option '$o'";
    }
  }
  %opt = (%$defaults, %opt);
  $self->set_filter_msgtype(
    delete $opt{filter_vendor},
    delete $opt{filter_msgtype}
  ) if defined($opt{filter_vendor} || $opt{filter_msgtype});
  for my $o (keys %opt) {
    my $v = $opt{$o};
    next unless defined $v;
    my $m = "set_$o";
    $self->$m($v);
  }
  $self;
}

###

sub breakloop { shift->_xs->breakloop() }

sub loop {
  my $self = shift;
  my $xs = $self->_xs;
  $xs->loop();
  $self->_init;
  $self;
}

### io wraps

sub _wrap_io {
  my $self = shift;
  my($io, %opt) = @_;
  #print STDERR "WRAP IO HERE: ", Dumper($io, \%opt);
  my $callbacks = $self->_callbacks;
  if (my $close_cb = $opt{close_cb}) {
    $callbacks->{$io} = sub {
      my $close_type = shift;
      #print STDERR "  SPEC: $io : ", $io->_spec, "\n";
      return \0 if $close_type == NMSG_CLOSE_TYPE_EOF;
      my $old_xs = $io->_xs;
      $close_cb->($io);
      if (! $io->opened) {
        delete $callbacks->{$io};
        return \0;
      }
      $old_xs->import_xs;
      $io->_xs->export_xs;
    };
  }
  return($io, $callbacks->{$io});
}

sub _add_input_io {
  my $self = shift;
  croak "not an input object $_[0]" unless $self->_is_input_io($_[0]);
  my($io, $cb) = $self->_wrap_io(@_);
  $self->_xs->add_input($io->_xs, $cb);
  push( @{ $self->_inputs }, $io );
}

sub _add_output_io {
  my $self = shift;
  croak "not an output object $_[0]" unless $self->_is_output_io($_[0]);
  my($io, $cb) = $self->_wrap_io(@_);
  $self->_xs->add_output($io->_xs, $cb);
  push( @{ $self->_outputs }, $io );
}

sub _is_input_io  { UNIVERSAL::isa($_[1], 'Net::Nmsg::Input' )   }
sub _is_output_io { UNIVERSAL::isa($_[1], 'Net::Nmsg::Output')   }

sub _is_io {
  my $self = shift;
  $self->_is_input_io || $self->_is_output_io;
}

### add inputs

sub add_input  {
  my $self = shift;
  my $io   = shift;
  return $self->_add_input_io($io, @_) if $self->_is_io($io);
  if (! ref $io && expand_socket_spec($io)) {
    $self->add_input_sock($io, @_);
  }
  elsif (is_channel($io)) {
    $self->add_channel_input($io, @_);
  }
  else {
    $self->_add_input_io($self->IO_INPUT->open($io, @_), @_);
  }
}

sub add_input_channel {
  my $self = shift;
  my $chan = shift || croak "channel alias required";
  my @spec = channel_lookup($chan);
  croak "not a channel alias '$chan'" unless @spec;
  $self->add_input_sock($_, @_) foreach @spec;
}
*add_input_chalias = \&add_input_channel;

sub add_input_file {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a nmsg file io $io" unless $io->is_file;
    return $self->_add_input_io($io, @_);
  }
  $self->_add_input_io($self->IO_INPUT->open_file($io, @_), @_);
}

sub add_input_sock {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a nmsg socket io $io" unless $io->is_sock;
    return $self->_add_input_io($io, @_);
  }
  $io = join('/', $io, shift) if @_ % 2;
  my @spec = expand_socket_spec($io);
  croak "not a socket spec '$io'" unless @spec;
  for $io (@spec) {
    $self->_add_input_io($self->IO_INPUT->open_sock($io, @_), @_);
  }
}

sub add_input_pres {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a pres file io $io" unless $io->is_pres;
    return $self->_add_input_io($io, @_);
  }
  $self->_add_input_io($self->IO_INPUT->open_pres($io, @_), @_);
}

sub add_input_pcap {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a pcap file io $io" unless $io->is_pcap;
    return $self->_add_input_io($io, @_);
  }
  $self->_add_input_io($self->IO_INPUT->open_pcap($io, @_), @_);
}

sub add_input_iface {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a pcap iface io $io" unless $io->is_iface;
    return $self->_add_input_io($io, @_);
  }
  $self->_add_input_io($self->IO_INPUT->open_iface($io, @_), @_);
}

### add outputs

sub add_output  {
  my $self = shift;
  my $io   = shift;
  return $self->_add_output_io($io, @_) if $self->_is_io($io);
  if (! ref $io && expand_socket_spec($io)) {
    $self->add_output_nmsg($io, @_);
  }
  else {
    $self->_add_output_io($self->IO_OUTPUT->open($io, @_), @_);
  }
}

sub add_output_channel {
  my $self = shift;
  my $chan = shift;
  my @sock = channel_lookup($chan);
  croak "not a channel '$chan'" unless @sock;
  $self->add_output_nmsg($_, @_) foreach @sock;
}
*add_output_chalias = \&add_output_channel;

sub add_output_file {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a nmsg file io $io" unless $io->is_file;
    return $self->_add_output_io($io, @_);
  }
  $self->_add_output_io($self->IO_OUTPUT->open_file($io, @_), @_);
}

sub add_output_sock {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a nmsg socket io $io" unless $io->is_sock;
    return $self->_add_output_io($io, @_);
  }
  $io = join('/', $io, shift) if @_ % 2;
  my @sock = expand_socket_spec($io);
  croak "not a socket '$io'" unless @sock;
  for $io (@sock) {
    $self->_add_output_io($self->IO_OUTPUT->open_sock($io, @_), @_);
  }
}

sub add_output_pres {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a presentation file io $io" unless $io->is_pres;
    return $self->_add_output_io($io, @_);
  }
  $self->_add_output_io($self->IO_OUTPUT->open_pres($io, @_), @_);
}

sub add_output_cb {
  my $self = shift;
  my $io   = shift;
  if ($self->_is_io($io)) {
    croak "not a callback io $io" unless $io->is_cb;
    return $self->_add_output_io($io, @_);
  }
  $self->_add_output_io($self->IO_OUTPUT->open_cb($io, @_), @_);
}

###

1;

__END__

=head1 NAME

Net::Nmsg::IO - Net::Nmsg - Perl interface for the nmsg IO loop


=head1 SYNOPSIS

  use Net::Nmsg::IO;

  my $io = Net::Nmsg::IO->new();

  my $cb = sub {
    my $msg = shift;
    print $msg->as_str, "\n";
  };

  $io->add_input('infile.nmsg');
  $io->add_output('127.0.0.1/9430');
  $io->add_output($cb);

  $io->loop;

=head1 DESCRIPTION

Net::Nmsg::IO is a perl interface to the IO manager of the nmsg network
data capture library.

=head1 CONSTRUCTOR

=over 4

=item new(%options)

Creates a new Net::Nmsg::IO object. Valid options are:

=over 4

=item mirrored

When enabled, mirrors input messages across all assigned outputs. The
default is to stripe incoming messages across outputs.

=item count

Stop processing after having written I<count> input messages to outputs
(mirrored messages count as one message)

=item interval

Stop processing after I<interval> seconds have passed.

=item filter_vendor

=item filter_msgtype

Filter messages for the specified message type. Both parameters are
required. If set, all inputs and outputs will share this filter.

=item filter_source

Specify a source filter for all inputs.

=item filter_operator

Specify an operator filter for all inputs.

=item filter_group

Specify a group filter for all inputs.

=back

=back

=head2 ACCESSORS

=over

=item set_mirrored($bool)

=item get_mirrored()

=item set_count($int)

=item get_count()

=item set_interval($secs)

=item get_interval()

=item set_filter_msgtype($vendor, $msgtype)

=item get_filter_msgtype()

=item set_filter_source($source)

=item get_filter_source()

=item set_filter_operator($operator)

=item get_filter_operator()

=item set_filter_group($group)

=item get_filter_group()

=back

=head2 METHODS

=over

=item loop()

Initiate processing on the assigned inputs and outputs. Processing
ceases when either the inputs are exausted or until C<breakloop()> is
called from within a callback.

=item breakloop()

When invoked from a callback, causes the processing loop to halt.

=item add_input($spec, %options)

Add an input to the IO loop. A reasonable attempt is made to determine
whether the specification is a file name (nmsg, pcap, pres), file handle
(nmsg), channel alias or socket specification (nmsg), network device
name (pcap), or reference to a Net::Nmsg::Input object, and is opened
accordingly. If for some reason this reasonable guess is not so
reasonable, use one of the specific input methods detailed below.

See L<Net::Nmsg::Input> for details on valid options.

=item add_output($spec, %options)

Add an output to the IO loop. A reasonable attempt is made to
determine whether the output specification is a socket specification
(nmsg), callback reference (per message), file name/handle (nmsg), or
reference to a Net::Nmsg::Output object. For other output types (such
as presentation format), use one of the specific output methods
detailed below.

See L<Net::Nmsg::Output> for details on valid options.

=item add_input_channel($channel, %opt)

Add input sockets associated with the given channel alias as defined by
the local nmsgtool installation.

=item add_input_file($file, %opt)

Add a NMSG formatted file as an input, specified either as a file name
or file handle.

=item add_input_sock($socket, %opt)
=item add_input_sock($host, $port, %opt)

Add a NMSG socket as an input, specified either as a socket
specification, socket handle, or host/port pair.

=item add_input_pres($file, vendor => $v, msgtype => $m, %opt)

Add a file in presentation format as an input, specified either
as a file name or handle. The I<vendor> and I<msgtype> parameters
are required.

=item add_input_pcap($file, vendor => $v, msgtype => $m, %opt)

Add a file in pcap format as an input, specefied as a file name. The
I<vendor> and I<msgtype> parameters are required.

=item add_input_iface($interface, vendor => $v, msgtype => $m, %opt)

Add a network interface (live pcap) as an input, specified as a network
device name. The I<vendor> and I<msgtype> parameters are required.

=item add_output_channel($channel, %opt)

Add output sockets assosicated with the given channel alias as defined by the local nmsgtool installation.

=item add_output_file($file, %opt)

Add a NMSG formatted file as an output, specified either as a file name
or handle.

=item add_output_sock($socket, %opt)

=item add_output_sock($host, $pair, %opt)

Add an output socket for NMSG formatted data, specified either as a
socket specification, socket handle, or host/port pair.

=item add_output_pres($file, %opt)

Add a file in presentation format as an output, specified either as a
file name or handle.

=item add_output_cb($code_ref, %opt)

Add the given callback reference as an output. The callback is passed a
reference to a message object for each message that makes it through
the filters. The process loop can be stopped by calling the loop()
method on the IO object. See L<Net::Nmsg::Msg> for more details on
message objects.

=back

=head1 SEE ALSO

L<Net::Nmsg::Input>, L<Net::Nmsg::Output>, L<Net::Nmsg::Msg>, L<nmsgtool(1)>

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
