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

package Net::Nmsg::Typemap;

use strict;
use warnings;
use Carp;

sub make_mapper {
  my($class, $type, $idx) = @_;
  croak "type required"  unless defined $type;
  croak "index required" unless defined $idx;
  my $map_makers = $class->map_makers;
  $map_makers->[$type] ? $map_makers->[$type]->($idx, $type) : ();
}

###

package Net::Nmsg::Typemap::Input;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Typemap );

use Net::Nmsg::Util qw( :field );

use Math::Int64;
use NetAddr::IP::Util qw( inet_aton ipv6_aton );

my @From;

sub map_makers { \@From };

sub _from_int64  {  int64_to_native(ref $_[0] ? $_[0] :  int64($_[0])) }
sub _from_uint64 { uint64_to_native(ref $_[0] ? $_[0] : uint64($_[0])) }

sub _from_ip { $_[0] =~ /:/ ? ipv6_aton($_[0]) : inet_aton($_[0]) }

$From[NMSG_FT_INT64 ] = sub { \&_from_int64  };
$From[NMSG_FT_UINT64] = sub { \&_from_uint64 };
$From[NMSG_FT_IP    ] = sub { \&_from_ip     };
$From[NMSG_FT_ENUM  ] = sub {
  my $idx = shift;
  sub {
    my($val, $msg) = @_;
    if (!/^\d+$/) {
      my $name = $val;
      $val = $msg->enum_name_to_value_by_idx($idx, $name);
      croak "unknown enum value '$name'" unless defined $val;
    }
    $val;
  };
};

#######

package Net::Nmsg::Typemap::Output;

use strict;
use warnings;
use Carp;

use base qw( Net::Nmsg::Typemap );

use Net::Nmsg::Util qw( :field );

use Math::Int64;
use NetAddr::IP::Util qw( ipv6_n2x inet_ntoa );

my @To;

sub map_makers { \@To };

sub _to_int64  {  native_to_int64($_[0]) }
sub _to_uint64 { native_to_uint64($_[0]) }

sub _to_ip { length $_[0] > 4 ? ipv6_n2x($_[0]) : inet_ntoa($_[0]) }

$To[NMSG_FT_INT64 ] = sub { \&_to_int64  };
$To[NMSG_FT_UINT64] = sub { \&_to_uint64 };
$To[NMSG_FT_IP    ] = sub { \&_to_ip     };

###

1;
