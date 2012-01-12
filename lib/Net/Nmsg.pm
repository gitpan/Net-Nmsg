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

package Net::Nmsg;

use 5.004_04;
use strict;
use warnings;
use Carp;

use vars qw( @EXPORT_OK %EXPORT_TAGS $VERSION );

require Exporter;
require DynaLoader;

use base qw( Exporter DynaLoader );

@EXPORT_OK = qw( DEBUG );

sub dl_load_flags { 0x01 } # global option

BEGIN {
  $VERSION = '0.09';
  bootstrap Net::Nmsg $VERSION;
}

my($Debug, $Autoclose);

sub DEBUG     { @_ ? set_debug    ($Debug     = shift) : $Debug     }
sub AUTOCLOSE { @_ ? set_autoclose($Autoclose = shift) : $Autoclose }

DEBUG(0);
AUTOCLOSE(0);

_nmsg_init_lib();

### predeclared utility functions

package Net::Nmsg::Util;

use strict;
use warnings;
use Carp;

sub _vendor_lookup {
  my $v = shift;
  croak "vendor id required" unless defined $v;
  my($vid, $vname);
  if ($v =~ /^\d+$/) {
    if (my $res = vid_to_vname($v)) {
      ($vid, $vname) = ($v, $res);
    }
  }
  else {
    if (my $res = vname_to_vid($v)) {
      ($vid, $vname) = ($res, $v);
    }
  }
  croak "uknown vendor '$v'" unless $vid;
  return($vid, $vname);
}

sub _msgtype_lookup {
  my($v, $m) = splice(@_, 0, 2);
  defined $v || Carp::confess "vendor id required\n";
  defined $m || Carp::confess "message name or id required\n";
  my($vid, $vname) = _vendor_lookup($v);
  my($mid, $mname);
  if ($m =~ /^\d+$/) {
    if (my $res = msgtype_to_mname($vid, $m)) {
      ($mid, $mname) = ($m, $res);
    }
  }
  else {
    if (my $res = mname_to_msgtype($vid, $m)) {
      ($mid, $mname) = ($res, $m);
    }
  }
  croak "unknown msgtype '$vid/$m'" unless $mid;
  return($vid, $mid, $vname, $mname);
}

###############################################################################
# XS class heirarchy and extras
###############################################################################

package Net::Nmsg::XS::io;

sub add_input  { @_ > 1 || return; $_[1]->export_xs; shift->_add_input (@_) }
sub add_output { @_ > 1 || return; $_[1]->export_xs; shift->_add_output(@_) }

###

package Net::Nmsg::XS::export_xs;

use strict;
use warnings;

my %Exported;

sub export_xs {
  my $self = shift;
  ++$Exported{$self};
  $self;
}

sub import_xs {
  my $self = shift;
  delete $Exported{$self};
  $self;
}

sub is_exported { $Exported{shift()} }

sub DESTROY {
  my $self = shift;
  #print STDERR "DESTROY XS $self ? ", $Exported{$self} ? "0\n" : "1\n";
  $self->destroy() unless $Exported{$self};
  delete $Exported{$self};
}

###

package Net::Nmsg::XS::base_xs;

use strict;
use warnings;

use base qw( Net::Nmsg::XS::export_xs );

sub set_filter_msgtype {
  my $self = shift;
  my($vid, $mid, $vname, $mname) = Net::Nmsg::Util::_msgtype_lookup(@_);
  $self->_set_filter_msgtype($vid, $mid);
  return($vname, $mname);
}

###

package Net::Nmsg::XS::input;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::XS::base_xs );

sub open_pcap {
  my $class = shift;
  my $nmsg_pcap = shift || croak "nmsg pcap ref required";
  my($vid, $mid, $vname, $mname) = Net::Nmsg::Util::_msgtype_lookup(@_);
  my $self = $class->_open_pcap($nmsg_pcap, $vid, $mid);
  $nmsg_pcap->export_xs if $self;
  $self;
}

sub open_pres {
  my $class = shift;
  my $fh = shift || croak "file handle required";
  my($vid, $mid, $vname, $mname) = Net::Nmsg::Util::_msgtype_lookup(@_);
  $class->_open_pres($fh, $vid, $mid);
}

sub is_file  { }
sub is_sock  { }
sub is_pres  { }
sub is_pcap  { }

###

package Net::Nmsg::XS::input_file;

use base qw( Net::Nmsg::XS::input );

use constant is_file => 1;

###

package Net::Nmsg::XS::input_sock;

use base qw( Net::Nmsg::XS::input );

use constant is_sock => 1;

###

package Net::Nmsg::XS::input_pres;

use base qw( Net::Nmsg::XS::input );

use constant is_pres => 1;

###

package Net::Nmsg::XS::input_pcap;

use base qw( Net::Nmsg::XS::input );

sub is_pcap  { shift->get_type == Net::Nmsg->NMSG_PCAP_TYPE_FILE }
sub is_iface { shift->get_type == Net::Nmsg->NMSG_PCAP_TYPE_LIVE }

######

package Net::Nmsg::XS::output;

use base qw( Net::Nmsg::XS::base_xs );

use Carp;

sub is_file  { }
sub is_sock  { }
sub is_pres  { }
sub is_cb    { }

sub write {
  my $self = shift;
  for my $m (@_) {
    eval { _write($self, $m->msg) };
    croak $@ if $@;
    $m->_flush;
  }
}

###

package Net::Nmsg::XS::output_file;

use base qw( Net::Nmsg::XS::output );

use constant is_file => 1;

###

package Net::Nmsg::XS::output_sock;

use base qw( Net::Nmsg::XS::output );

use constant is_sock => 1;

###

package Net::Nmsg::XS::output_pres;

use base qw( Net::Nmsg::XS::output );

use constant is_pres => 1;

###

package Net::Nmsg::XS::output_cb;

use base qw( Net::Nmsg::XS::output );

use constant is_cb => 1;

######

package Net::Nmsg::XS::nmsg_pcap;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::XS::export_xs );

sub open_input {
  my $class = shift;
  my $pcap  = shift || croak "pcap xs io required";
  my $self  = $class->_input_open($pcap);
  $pcap->export_xs if $self;
  $self;
}

###

package Net::Nmsg::XS::pcap;

use base qw( Net::Nmsg::XS::export_xs );

###############################################################################

1;

__END__

=pod

=head1 NAME

Net::Nmsg - Perl extension for the NMSG message interchange library

=head1 SYNOPSIS

  # The primary interface involves using the IO object; an IO
  # object can be assigned multiple inputs and outputs and
  # relies on the underlying threaded library to distribute
  # messages from the inputs to the outputs.

  use Net::Nmsg::IO;

  my $io = Net::Nmsg::IO->new();

  my $c = 0;

  my $cb = sub {
    my $msg = shift;
    print join(' ', "msg $c :", $msg->msgtype), "\n";
    print $msg->as_str, "\n\n";
    ++$c;
  };

  $io->add_input('infile.nmsg');
  $io->add_output($cb);

  $io->loop;

  # Another way of using the interface is through individual
  # input and output objects, handling the messsage distribution
  # loop in perl itself. Input and output handles are similar
  # to IO::Handle objects in how they can be used.

  use Net::Nmsg::Input;

  my $h = Net::Nmsg::Input->open('infile.nmsg');
  while (my $msg = <$h>) {
    ...
  }

  # alternatively...

  my $io = Net::Nmsg::Input->open('infile.nmsg');
  $io->loop($cb);


=head1 DESCRIPTION

Net::Nmsg is a perl binding to libnmsg, the reference implementation
of the NMSG binary structured message interchange format. The NMSG
documentation describes the format as:

    The NMSG format is an efficient encoding of typed, structured data
    into payloads which are packed into containers which can be
    transmitted over the network or stored to disk. Each payload is
    associated with a specific message schema. Modules implementing a
    certain message schema along with functionality to convert between
    binary and presentation formats can be loaded at runtime by
    libnmsg. nmsgtool provides a command line interface to control the
    transmission, storage, creation, and conversion of NMSG payloads.

The modules of primary use are Net::Nmsg::IO, Net::Nmsg::Input, and
Net::Nmsg::Output. Individual messages are handled through a type
specific subclass of Net::Nmsg::Msg depending on what vendor plugins
are present on the host system.

=head1 SEE ALSO

L<Net::Nmsg::IO>, L<Net::Nmsg::Input>, L<Net::Nmsg::Output>, L<nmsgtool(1)>

The nmsg library can be downloaded from: ftp://ftp.isc.org/isc/nmsg/

The pcap library can be downloaded from: http://www.tcpdump.org/


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
