# Copyright (C) 2010 by Carnegie Mellon University
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

package Net::Nmsg::Output;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Layer );

use Net::Nmsg::Util qw( :io :buffer :vendor );
use Net::Nmsg::Msg;
use Net::Nmsg::Handle;

use constant HANDLE_IO => 'Net::Nmsg::Handle';
use constant OUTPUT_XS => 'Net::Nmsg::XS::output';

my %Defaults = (

  # common
  filter_vendor  => undef,
  filter_msgtype => undef,

  # nmsg
  source   => undef,
  operator => undef,
  group    => undef,

  # nmsg/stream
  buffered => 1,
  zlibout  => 0,
  rate     => NMSG_DEFAULT_SO_RATE,
  freq     => NMSG_DEFAULT_SO_FREQ,
  bufsz    => undef, # depends on stream/socket

  # pres
  endline => $/,
);

sub _defaults { \%Defaults }

sub get_filter_msgtype { shift->_get_xs_opt(filter_msgtype => @_) }
sub get_operator       { shift->_get_xs_opt(operator       => @_) }
sub get_source         { shift->_get_xs_opt(source         => @_) }
sub get_group          { shift->_get_xs_opt(group          => @_) }
sub get_buffered       { shift->_get_xs_opt(buffered       => @_) }
sub get_zlibout        { shift->_get_xs_opt(zlibout        => @_) }
sub get_rate           { shift->_get_xs_opt(rate           => @_) }
sub get_endline        { shift->_get_xs_opt(endline        => @_) }

sub set_filter_msgtype { shift->_set_xs_opt(filter_msgtype => @_) }
sub set_operator       { shift->_set_xs_opt(operator       => @_) }
sub set_source         { shift->_set_xs_opt(source         => @_) }
sub set_group          { shift->_set_xs_opt(group          => @_) }
sub set_buffered       { shift->_set_xs_opt(buffered       => @_) }
sub set_zlibout        { shift->_set_xs_opt(zlibout        => @_) }
sub set_rate           { shift->_set_xs_opt(rate           => @_) }
sub set_endline        { shift->_set_xs_opt(endline        => @_) }

###

sub is_file { (shift->_xs || return)->is_file }
sub is_sock { (shift->_xs || return)->is_sock }
sub is_pres { (shift->_xs || return)->is_pres }
sub is_cb   { (shift->_xs || return)->is_cb   }

###

sub _map_opts {
  my $self = shift;
  my %opt  = @_;
  my $vendor  = delete $opt{filter_vendor};
  my $msgtype = delete $opt{filter_msgtype};
  return %opt unless defined $vendor || defined $msgtype;
  $self->error("vendor and msgtype required") && return
    unless defined $vendor && defined $msgtype;
  $opt{filter_msgtype} = [$vendor, $msgtype];
  #
  my $rate = delete $opt{rate};
  my $freq = delete $opt{freq};
  $opt{rate} = [$rate, $freq];
  %opt;
}

sub _init_output {
  my $self = shift;
  my($spec, $io, $xs, %opt) = @_;
  *$self->{_spec} = $spec;
  *$self->{_io}   = $io;
  *$self->{_xs}   = $xs;
  $self->_dup_io_w;
  $self->_init_opts(%opt);
  $self;
}

sub open {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  if (Net::Nmsg::Util::is_callback($spec)) {
    return $self->open_cb($spec, %opt)
      || ($fatal ? croak $self->error : return);
  }
  elsif (Net::Nmsg::Util::looks_like_socket($spec)) {
    return $self->open_sock($spec, %opt)
      || ($fatal ? croak $self->error : return);
  }
  else {
    return $self->open_file($spec, %opt)
      || ($fatal ? croak $self->error : return);
  }
}

sub open_file {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  $opt{bufsz} = NMSG_WBUFSZ_MAX unless defined $opt{bufsz};
  my $io;
  eval { $io = $self->HANDLE_IO->open_output_file($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  my $xs;
  eval { $xs = $self->OUTPUT_XS->open_file($io, $opt{bufsz}) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self->_init_output($spec, $io, $xs, %opt);
}

sub open_sock {
  my $self = shift;
  my $spec = @_ % 2 ? shift : join('/', splice(@_, 0, 2));
  ($self, $spec, my($fatal, %opt)) = $self->_open_init($spec, @_);
  $opt{bufsz} = NMSG_WBUFSZ_ETHER unless defined $opt{bufsz};
  my $io;
  eval { $io = $self->HANDLE_IO->open_output_sock($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  my $xs;
  eval { $xs = $self->OUTPUT_XS->open_sock($io, $opt{bufsz}) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self->_init_output($spec, $io, $xs, %opt);
}

sub open_pres {
  my($self, $spec, $fatal, %opt) = shift->_open_init(@_);
  my $io;
  eval { $io = $self->HANDLE_IO->open_output_file($spec, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  my $xs;
  eval { $xs = $self->OUTPUT_XS->open_pres($io) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self->_init_output($spec, $io, $xs, %opt);
}

sub open_cb {
  my($self, $cb, $fatal, %opt) = shift->_open_init(@_);
  my $io;
  eval { $io = $self->HANDLE_IO->open_output_cb($cb, %opt) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  my $xs;
  eval { $xs = $self->OUTPUT_XS->open_callback($cb) };
  $@ && $self->error($@) && ($fatal ? croak $self->error : return);
  $self->_init_output($cb, $io, $xs, %opt);
}

### perl IO

sub write {
  push(@_, $_) if @_ == 1 && defined $_;
  (shift->_xs || croak "attempted write on closed output")->write(@_);
}

###

1;

__END__

=head1 NAME

Net::Nmsg::Output - Perl interface for nmsg outputs

=head1 SYNOPSIS

  use Net::Nmsg::Input;
  use Net::Nmsg::Output;

  my $in  = Net::Nmsg::Input->open('input.nmsg');
  my $out = Net::Nmsg::Output->open('output.nmsg');

  my $c = 0;

  while (my $msg = <$in>) {
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

Net::Nmsg::Output provides the perl interface for the
Net::Nmsg::XS::output extension.

=head1 CONSTRUCTORS

=over

=item open($spec, %options)

Creates and opens new output object. The output can be specified as a
file name or handle, callback reference, or socket.

Available options:

=over

=item filter_vendor

=item filter_msgtype

Restricts the output to messages of the given vendor and msgtype. Both
are required if filtering is desired.

=item source

=item operator

=item group

Set the source, operator, and group fields on outputs (nmsg only)

=item buffered_io

Control whether or not the output socket is buffered (default: 1).

=item zlibout

Enable or disable zlib compression of output (nmsg only)

=item rate
=item freq

Limit the payload output rate


=item bufsz

Set the buffer size for the output (the default value is based on
whether the output is a file or socket)

=item endline

Set the line ending character for presentation outputs.

=back

=item open_nmsg($spec, %options)

Opens an output in nmsg format, as specified by file name, file handle,
socket specification, or socket handle.

=item open_pres($spec, %options)

Opens an output in presentation format, as specified by file name
or file handle. The 'filter_vendor' and 'filter_msgtype' options
are required.

=item open_cb($callback)

Opens a callback output using the provided code reference. The callback
will be invoked with a Net::Nmsg::Msg reference each time a message is
'written' to the output.

=back

=head2 ACCESSORS

=over

=item set_msgtype($vendor, $msgtype)

=item get_msgtype

=item set_source($source)

=item get_source()

=item set_operator($operator)

=item get_operator()

=item set_group($group)

=item get_group()

=item set_rate($rate, $freq)

=item get_rate()

=item set_buffered_io($bool)

=item get_buffered_io()

=item set_zlibout($bool)

=item get_zlibout()

=item set_endline($eol)

=item get_endline()

=item get_bufsz()

=back


=head2 METHODS

=over

=item write($msg)

Write the given Net::Nmsg::Msg object to this output.

=back

=head1 SEE ALSO

L<Net::Nmsg::IO>, L<Net::Nmsg::Input>, L<Net::Nmsg::Msg>, L<nmsgtool(1)>

=head1 AUTHOR

Matthew Sisk, E<lt>sisk@cert.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Carnegie Mellon University

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, as published by
the Free Software Foundation, under the terms pursuant to Version 2,
June 1991.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

=cut
