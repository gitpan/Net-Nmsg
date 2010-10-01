#!/usr/bin/perl

use strict;
use warnings;

use Net::Nmsg::IO;

use Net::DNS::ToolKit::RR;
use Encode::Escape;

my $io = Net::Nmsg::IO->new;

my($get, $put, $parse) = Net::DNS::ToolKit::RR->new;

sub data_escape { encode('unicode-escape', shift) }

sub process_msg_ch205 {
  my $m = shift || return;
  print "HI $m\n";
  my($name, $type, $class, $ttl, $rdlength, @rdata) = $parse->RR(
    $m->get_rrname,
    $m->get_rrtype,
    $m->get_rrclass,
    $m->get_rrttl,
    $m->get_rrttl,
    0,
    $m->get_rdata,
  );
  print $m->header_as_str, "\n";
  print "rrname: $name\nrrclass: $class\nrrtype: $type\n";
  for my $rdata (@rdata) {
    print "rdata: ", data_escape($rdata), "\n";
  }
  print "\n";
}

$io->add_input_channel('ch205');
$io->set_filter_msgtype(ISC => 'dns');
$io->add_output_cb(\&process_msg_ch205);
$io->loop;
