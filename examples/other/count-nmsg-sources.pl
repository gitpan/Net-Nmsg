#!/usr/bin/perl

use strict;
use warnings;

use Net::Nmsg::IO;

my(%srcips, %dstips);

my $count = 0;

sub process_msg_ch202 {
  my $m = shift;
  ++$count;
  if (! $count % 100000) {
    printf "len(srcips)=%d len(dstips)=%d\n",
           scalar keys %srcips, scalar keys %dstips;
  }
  if ($m->get_proto == 17 && $m->get_srcport == 53) {
    ++$srcips{$m->get_srcip};
    ++$dstips{$m->get_dstip};
  }
}

my $io = Net::Nmsg::IO->new;

$io->add_input_chalias('ch202');
$io->set_filter_msgtype(ISC => 'ncap');
$io->add_output_cb(\&process_msg_ch202);
$io->loop;
