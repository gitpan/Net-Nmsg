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

package Net::Nmsg::Layer;

use strict;
use warnings;
use Carp;

use Symbol ();

sub _defaults { {} }

sub defaults {
  my $defaults = shift->_defaults;
  wantarray ? %$defaults : {%$defaults};
}

sub opt_required { }

sub _io   { *{shift()}->{_io  } }
sub _xs   { *{shift()}->{_xs  } }
sub _spec { *{shift()}->{_spec} }
sub _opt  { *{shift()}->{_opt } }

###

sub _get_io_opt {
  my $self = shift;
  $self->_get_inner_opt($self->_io, @_);
}

sub _set_io_opt {
  my $self = shift;
  $self->_set_inner_opt($self->_io, @_);
}

sub _get_xs_opt {
  my $self = shift;
  $self->_get_inner_opt($self->_xs, @_);
}

sub _set_xs_opt {
  my $self = shift;
  $self->_set_inner_opt($self->_xs, @_);
}

sub _get_opt {
  my $self = shift;
  my $opt  = shift;
  my $v = *$self->{_opt}{$opt} || [];
  return $v->[0] if @$v == 1;
  wantarray ? @$v : [@$v];
}

sub _get_inner_opt {
  my $self = shift;
  my($io, $opt) = splice(@_, 0, 2);
  if ($io) {
    my $m = 'get_' . $opt;
    my $v;
    eval { $v = $io->$m() };
    if ($@) {
      croak $@ if $@ !~ /locate\s+object\s+method/i;
    }
    else {
      return $self->_set_opt($opt, $v);
    }
  }
  $self->_get_opt($opt);
}

sub _set_opt {
  my $self = shift;
  my $opt  = shift;
  if (@_ == 1 && ref $_[0] eq 'ARRAY') {
    @_ = @{$_[0]};
  }
  *$self->{_opt}{$opt} = [@_] if @_;
  $self->_get_opt($opt);
}

sub _set_inner_opt {
  my $self = shift;
  my($io, $opt) = splice(@_, 0, 2);
  if (@_ == 1 && ref $_[0] eq 'ARRAY') {
    @_ = @{$_[0]};
  }
  my $m = 'set_' . $opt;
  eval { $io->$m(@_) };
  croak $@ if $@ && $@ !~ /locate\s+object\s+method/i;
  $self->_set_opt($opt, @_);
}

### construction/opening

sub _map_opts { shift; @_ }

sub _open_init {
  my $self  = shift;
  my $fatal;
  if (! ref $self) {
    $self  = $self->new;
    $fatal = 1;
  }
  croak "spec required" unless @_;
  my $spec     = shift;
  my %opt      = (%{$self->_opt}, @_);
  my $defaults = $self->_defaults;
  for my $o (keys %opt) {
    if (! exists $defaults->{$o} && $o !~ /^_/) {
      warn "unknown option '$o'";
      delete $opt{$o};
    }
  }
  for my $o (grep { defined $_ } $self->opt_required) {
    croak "option '$o' required" unless defined $opt{$o};
  }
  return($self, $spec, $fatal, $self->_map_opts(%$defaults, %opt));
}

sub new {
  my $class = shift;
  $class = ref $class || $class;
  my $self = Symbol::gensym();
  bless $self, $class;
  *$self->{_opt} = {};
  $self->open(@_) if @_;
  $self;
}

sub _dup_io_r {
  my $self = shift;
  my $fh = @_ ? shift : $self->_io;
  return unless defined $fh && defined fileno($fh);
  open($self, '<&=', $fh) || die "problem duping read fh : $!";
  $self;
}

sub _dup_io_w {
  my $self = shift;
  my $fh = @_ ? shift : $self->_io;
  return unless defined $fh && defined fileno($fh);
  open($self, '>&=', $fh) || die "problem duping write fh : $!";
  $self;
}

sub _init_opts {
  my $self = shift;
  my %opt  = @_;
  for my $o (keys %opt) {
    next if $o =~ /^_/;
    my $v = $opt{$o};
    next unless defined $v;
    my $m = 'set_' . $o;
    $self->$m($v) if UNIVERSAL::can($self, $m);
  }
  $self;
}

### IO layer

sub error {
  my $self = shift;
  @_ ? *$self->{_error} = shift : *$self->{_error};
}

sub clear_error { *shift->{_error} = undef }

sub close {
  my $self  = shift;
  %{*$self} = ();
  undef *$self if $] eq "5.008"; # cargo cult; see IO::String
  1;
}

sub opened { (shift->_io || return)->opened }
sub fileno { (shift->_io || return)->fileno }
sub stat   { (shift->_io || return)->stat   }

sub blocking { (shift->_io || croak "Bad filehandle")->blocking }
sub eof      { (shift->_io || croak "Bad filehandle")->eof      }

sub _fake_stat {
  my $self = shift;
  return unless $self->opened;
  return 1 unless wantarray;
  return (
    undef, # dev
    undef, # ino
    0666,  # mode
    1,     # links
    $>,    # uid
    $),    # gid
    undef, # did
    0,     # size
    undef, # atime
    undef, # mtime
    undef, # ctime
    0,     # blksize
    0,     # blocks
  );
}

###

1;
