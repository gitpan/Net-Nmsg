#!/usr/bin/perl

use strict;
use warnings;

use Net::Nmsg::Input;

use IO::Select;

@ARGV || die "socket spec required\n";

my $spec = @ARGV == 2 ? join('/', @ARGV) : shift;

my $n = Net::Nmsg::Input->open($spec);

my $s = IO::Select->new($n);

while (1) {
  if ($s->can_read(1)) {
    while (my $m = $n->read) {
      print "got a message\n";
    }
  }
  else {
    print "no messages!\n";
  }
}
