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

package Net::Nmsg::Msg;

use strict;
use warnings;
use Carp;

###

use Net::Nmsg::Util qw( :field );
use Net::Nmsg::Typemap;

use constant MSG   => 0;
use constant STAGE => 1;
use constant DIRTY => 2;

my $Input_Typemap_Class  = 'Net::Nmsg::Typemap::Input';
my $Output_Typemap_Class = 'Net::Nmsg::Typemap::Output';
my $XS_Msg_Class         = 'Net::Nmsg::XS::msg';

my @Modules;

sub modules { @Modules }

{
  # build sub classes based on modules present
  no strict 'refs';
  my $pkg = __PACKAGE__;
  for my $m (Net::Nmsg::Util::_dump_msgtypes()) {
    my($vid, $mid, $vname, $mname) = @$m;
    my $class = join('::', $pkg, $vname, $mname);
    push(@Modules, $class);
    #print STDERR "ASSIGN *$class\::ISA\n";
    eval <<__CLASS;
package $class;

use base qw( $pkg );

use Net::Nmsg::Util;

use constant VID    => $vid;
use constant MID    => $mid;
use constant type   => qw( $mname );
use constant vendor => qw( $vname );

my \$Mod = Net::Nmsg::Util::_msgmod_lookup($vid, $mid);
die \$@ if \$@;

sub _new_msg { $XS_Msg_Class->init(\$Mod) }

__CLASS
  die "class construction failed : $@" if $@;
  $class->_load_methods;
  }
}

sub new {
  my $self = bless [], shift;
  $self->[MSG] = shift;
  $self;
}

sub msg {
  my $self = shift;
  $self->_pack if $self->[DIRTY];
  $self->[MSG];
}

sub _msg {
  my $self = shift;
  $self->[MSG] ||= $self->_new_msg;
}

sub source {
  my $self = shift;
  $self->_msg->set_source(shift) if @_;
  $self->_msg->get_source()
}

sub operator {
  my $self = shift;
  $self->_msg->set_operator(shift) if @_;
  $self->_msg->get_operator()
}

sub group {
  my $self = shift;
  $self->_msg->set_group(shift) if @_;
  $self->_msg->get_group()
}

sub time {
  my $self = shift;
  $self->_msg->set_time(@_) if @_;
  $self->_mgs->get_time();
}

sub fields_present {
  my $self   = shift;
  my $fields = $self->_fields;
  my $flags  = $self->_flags;
  my @fp;
  for my $i (0 .. $#$fields) {
    next if $flags->[$i] & NMSG_FF_HIDDEN;
    my $f = $fields->[$i];
    my $method = 'get_' . $f;
    push(@fp, $f) if UNIVERSAL::can($self, $method);
  }
  @fp;
}

###

sub header_as_str {
  my $self = shift;
  my $msg  = $self->_msg || return '';
  my($ts, $nsec) = $msg->get_time;
  my($s, $min, $h, $d, $m, $y) = (gmtime($ts))[0..5];
  $y += 1900; ++$m;
  my @str = sprintf("[%04d-%02d-%02d %02d:%02d:%02d.%09d]",
                    $y, $m, $d, $h, $min, $s, $nsec);
  push(@str, sprintf("[%d:%d %s %s]",
             $self->VID, $self->MID, $self->type, $self->vendor));
  my $src = $msg->get_source;
  push(@str, $src ? sprintf("[%08x]", $src) : '[]');
  join(' ',
    @str,
    map { $_ ? "[$_]" : '[]' } ($msg->get_operator, $msg->get_group)
  );
}

sub as_str {
  my $self = shift;
  my $eol  = shift || "\n";
  join($eol, $self->header_as_str, $self->_msg->message_to_pres($eol));
}

sub _debug_as_str {
  my $self   = shift;
  my $eol    = shift || "\n";
  my @str    = $self->header_as_str;
  my $fields = $self->_fields;
  my $flags  = $self->_flags;
  for my $i (0 .. $#$fields) {
    next if $flags->[$i] & (NMSG_FF_HIDDEN | NMSG_FF_NOPRINT);
    my $f = $fields->[$i];
    my $m = 'get_' . $f;
    my @v = $self->$m;
    @v && push(@str, sprintf("%s: %s", $f, join(', ', @v)));
  }
  join($eol, @str, '');
}


###

sub _unpack {
  return $_[0]->[STAGE] if $_[0]->[STAGE];
  my $msg = $_[0]->[MSG] ||= $_[0]->_new_msg;
  my @unpacked;
  for my $i (0 .. $_[0]->count - 1) {
    my @v = $msg->get_field_vals_by_idx($i);
    #print STDERR "UNPACK[$i] : ", Dumper(\@v), "\n";
    push(@unpacked, @v ? \@v : undef);
  }
  $_[0]->[STAGE] = \@unpacked;
}

sub _pack {
  my $unp   = $_[0]->[DIRTY] || return;
  my $flags = $_[0]->_flags;
  my $msg   = $_[0]->[MSG] ||= $_[0]->_new_msg;
  for my $i (0 .. $#$unp) {
    my $val = $unp->[$i];
    croak "field " . $_[0]->fields->[$i] . " is required"
      unless defined $val || !($flags->[$i] & NMSG_FF_REQUIRED);
    for my $f (0 ..$#$val) {
      #print STDERR "PACK[$i:$f] : ", $val->[$f], "\n";
      $msg->set_field_by_idx($i, $f, $val->[$f]);
    }
  }
  $_[0]->[DIRTY] = undef;
}

###

sub _setter {
  my($class, $idx, $flags, $mapper) = @_;
  my $repeated = $flags & NMSG_FF_REPEATED;
  if ($mapper) {
    return sub {
      my $self = shift;
      @_ || return;
      my $unp = $self->[DIRTY] ||= $self->_unpack;
      my $msg = $self->[MSG]   ||= $self->_new_msg;
      my $val = $unp->[$idx]   ||= [];
      @_ = pop if @_ > 1 && !$repeated;
      @$val = grep { defined $_ }
              map  { $mapper->($_, $msg) }
              grep { defined $_ }
              @_;
      $unp->[$idx] = undef unless @$val;
    };
  }
  else {
    return sub {
      my $self = shift;
      @_ || return;
      my $unp = $self->[DIRTY] ||= $self->_unpack;
      my $msg = $self->[MSG]   ||= $self->_new_msg;
      my $val = $unp->[$idx]   ||= [];
      @_ = pop if @_ > 1 && !$repeated;
      @$val = grep { defined $_ } @_;
      $unp->[$idx] = undef unless @$val;
    };
  }
}
              
sub _pusher {
  my($class, $idx, $flags, $mapper) = @_;
  croak "not a repeated field ($idx)" unless $flags & NMSG_FF_REPEATED;
  return sub {
    my $self = shift;
    @_ || return;
    my $unp = $self->[DIRTY] ||= $self->_unpack;
    my $msg = $self->[MSG]   ||= $self->_new_msg;
    my $val = $unp->[$idx]   ||= [];
    @_ = grep { defined $_ } @_;
    @_ || return;
    #print STDERR "SUPPOSED ADD $idx => ", join(', ', @_), "\n";
    if ($mapper) {
      push(@$val, grep { defined $_ } map { $mapper->($_, $msg) } @_);
    }
    else {
      push(@$val, @_);
    }
    $unp->[$idx] = undef unless @$val;
  };
}

sub _getter {
  my($class, $idx, $flags, $mapper) = @_;
  my $repeated = $flags & NMSG_FF_REPEATED;
  if ($mapper) {
    if ($repeated) {
      # plural mapped
      return sub {
        my $msg = $_[0]->[MSG] ||= $_[0]->_new_msg;
        my @val;
        if (my $unp = $_[0]->[STAGE]) {
          # use unpacked if available
          if ($unp->[$idx]) {
            @val = map { $mapper->($_, $msg) } @{$unp->[$idx]};
          }
        }
        else {
          # otherwise query the struct directly
          @val = map { $mapper->($_, $msg) }
                 $msg->get_field_vals_by_idx($idx);
        }
        wantarray ? @val : \@val;
      };
    }
    else {
      # singular mapped
      return sub {
        my $msg = $_[0]->[MSG] ||= $_[0]->_new_msg;
        my $val;
        if (my $unp = $_[0]->[STAGE]) {
          # use unpacked if available
          return unless defined($val = $unp->[$idx]);
          return unless defined($val = $val->[0]);
        }
        else {
          # otherwise query the struct directly
          return unless defined($val = $msg->get_field_by_idx($idx, 0));
        }
        return $mapper->($val, $msg);
      };
    }
  }
  else {
    if ($repeated) {
      # plural unmapped
      return sub {
        my $msg = $_[0]->[MSG] ||= $_[0]->_new_msg;
        my @val;
        if (my $unp = $_[0]->[STAGE]) {
          # use unpacked if available
          @val = @{ $unp->[$idx] || [] };
        }
        else {
          # otherwise query the struct directly
          @val = $msg->get_field_vals_by_idx($idx);
        }
        wantarray ? @val : \@val;
      };
    }
    else {
      # singular unmapped
      return sub {
        my $msg = $_[0]->[MSG] ||= $_[0]->_new_msg;
        my $val;
        if (my $unp = $_[0]->[STAGE]) {
          # use unpacked if available
          if ($val = $unp->[$idx]) {
            $val = $val->[0];
          }
        }
        else {
          # otherwise query the struct directly
          $val = $msg->get_field_by_idx($idx, 0);
        }
        defined $val ? $val : ();
      };
    }
  }
}

###

sub _msg_descr {
  my($class, $msg) = @_;
  my(@fields, @types, @flags);
  my $i = 0;
  while (defined(my $val = $msg->get_field_name($i))) {
    $fields [$i] = $val;
    $types  [$i] = $msg->get_field_type_by_idx ($i);
    $flags  [$i] = $msg->get_field_flags_by_idx($i);
    ++$i;
  }
  return(\@fields, \@types, \@flags);
}

sub _load_methods {
  my $class = shift;
  $class = ref $class || $class;

  my $types_by_val = field_types_by_val();
  my $flags_by_val = field_flags_by_val();

  my $msg = $class->_new_msg;
  my($fields, $types, $flags) = $class->_msg_descr($msg);

  my(@tlabels, @flabels);

  no strict "refs";
  *{ "$class\::_fields" } = sub { $fields };
  *{ "$class\::_types"  } = sub { $types  };
  *{ "$class\::_flags"  } = sub { $flags  };
  *{ "$class\::fields"  } = sub { wantarray ? @$fields : [@$fields] };
  *{ "$class\::types"   } = sub { wantarray ? @tlabels : [@tlabels] };
  *{ "$class\::count"   } = sub { scalar @$fields };
  *{ "$class\::flags"   } = sub {
    my @flags;
    for my $f (@flabels) {
      push(@flags, {%$f});
    }
    wantarray ? @flags : \@flags;
  };
  for my $i (0 .. $#$fields) {
    my $key = $fields->[$i];
    my $ft  = $types ->[$i];
    my $ff  = $flags ->[$i];
    $tlabels[$i] = $types_by_val->{$ft};
    my %labels;
    if ($ff) {
      my $c = 0;
      my $fff = $ff;
      while ($fff) {
        if ($fff & 0x01) {
          my $v = 2 ** $c;
          $labels{$flags_by_val->{$v} || 'UNKNOWN'} = $v;
        }
        ++$c;
        $fff >>= 1;
      }
    }
    $flabels[$i] = \%labels;
    my $repeated = $ff & NMSG_FF_REPEATED;
    my $in_map   = $Input_Typemap_Class ->make_mapper($ft, $i);
    my $out_map  = $Output_Typemap_Class->make_mapper($ft, $i);
    *{ "$class\::get_$key" } = $class->_getter($i, $ff, $out_map);
    *{ "$class\::set_$key" } = $class->_setter($i, $ff, $in_map);
    *{ "$class\::add_$key" } = $class->_pusher($i, $ff, $in_map)
      if $repeated;
    *{ "$class\::get_raw_$key" } = $class->_getter($i, $ff);
    *{ "$class\::set_raw_$key" } = $class->_setter($i, $ff);
    *{ "$class\::add_raw_$key" } = $class->_pusher($i, $ff)
      if $repeated;
  }
}

###

1;

__END__

=pod

=head1 NAME

Net::Nmsg::Msg - Perl interface for messages from the NMSG library

=head1 SYNOPSIS

  use Net::Nmsg::Output;
  use Net::Nmsg::Input;
  use Net::Nmsg::Msg;

  # Each message type (vendor/msgtype) gets its own subclass with
  # methods specific to the fields for that type. For example:

  my $o = Net::Nmsg::Output->open('127.0.0.1/9430');
  my $m = Net::Nmsg::ISC::ipconn->new();
  for my $i (0 .. 99) {
    $m->set_srcip("127.0.0.$i");
    $m->set_dstip("127.1.0.$i");
    $m->set_srcport($i);
    $m->set_dstport(65535 - $i);
    $o->write($m);
  }

  my $c = 0;
  my $i = Net::Nmsg::Input->open('input.nmsg');
  while (my $m = $i->read) {
    print "message $c vendor ", $m->vendor, " type ", $m->type, "\n"
    print $m->as_str, "\n";
    ++$c;
  }

=head1 DESCRIPTION

Net::Nmsg::Msg is the base class for NMSG messages. Each vendor/msgtype
has a tailored subclass for handling fields particular to that type.

=head1 METHODS

=over

=item modules()

Returns a list of all message module classes installed on the system.

=item vendor()

The name of the vendor of this message module.

=item type()

The message type of this message module.

=item source([source])

Return or set the source ID of this message.

=item operator([operator])

Return or set the operator ID of this message.

=item group([group])

Return or set the group of this message.

=item time([time_sec, time_nsec])

Return or set the timestamp of this message. Accepts and returns
two integer values representing seconds and nanoseconds.

=item fields()

A list of possible field names for this message module.

=item fields_present()

A list of fields actually present in a message instance.

=item headers_as_str()

Renders the headers of a message (vendor, type, source, operator, group)
as a string.

=item as_str()

Renders the entire message, headers plus fields and their values
as a string.

=back

=head1 ACCESSORS

Each field of a message has several methods associated with it. Replace
'fieldname' with the actual name of the field:

  get_fieldname()
  get_raw_fieldname()

  set_fieldname($val)
  set_raw_fieldname($packed_val)

Fields that are 'repeated' accept multiple values in the setters and
return (possibly) multiple values from the getters. Repeated fields have
these additional methods associated with them which push values onto the
list of existing values:

  add_fieldname(@vals)
  add_raw_fieldname(@packed_vals)

There is no difference between the plain and raw versions of these
methods if the field is one of the following data types:

  NMSG_FT_BYTES
  NMSG_FT_STRING
  NMSG_FT_MLSTRING
  NMSG_FT_UINT16
  NMSG_FT_UINT32
  NMSG_FT_INT16
  NMSG_FT_INT32
  NMSG_FT_DOUBLE
  NMSG_FT_BOOL

The following field types behave differently since there are no native
perl types for them:

  field           mode  type   returns/accepts
  -------------------------------------------------------------
  NMSG_FT_IP      get          IPv4/IPv6 strings
  NMSG_FT_IP      set          IPv4/IPv6 strings
  NMSG_FT_IP      get   raw    IPv4/IPv6 packed network order
  NMSG_FT_IP      set   raw    IPv4/IPv6 packed network order

  NMSG_FT_INT64   get          Math::Int64
  NMSG_FT_INT64   set          Math::Int64 or string
  NMSG_FT_INT64   get   raw    64-bit integer packed native
  NMSG_FT_INT64   set   raw    64-bit integer packed native

  NMSG_FT_UINT64  *     *      same as above but unsigned

  NMSG_FT_ENUM    get          string
  NMSG_FT_ENUM    set          string
  NMSG_FT_ENUM    get   raw    int
  NMSG_FT_ENUM    set   raw    int

=head1 SEE ALSO

L<Net::Nmsg::IO>, L<Net::Nmsg::Input>, L<Net::Nmsg::Output>, L<nmsgtool(1)>

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
