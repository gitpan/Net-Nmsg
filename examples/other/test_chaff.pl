#!/usr/bin/perl

use strict;
use warnings;

use Net::Nmsg::IO;

use Net::DNS::ToolKit::RR;
use Encode::Escape;

my $io = Net::Nmsg::IO->new;

sub process_chaff {
  my $m = shift;
  print STDERR $m->header_as_str, "\n";
}

$io->set_filter_group('dns_parse_failure');
$io->add_input_sock('10.0.206.255', 8430);
$io->add_output_cb(\&process_chaff);
$io->loop;
