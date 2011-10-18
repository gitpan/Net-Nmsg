#!/usr/bin/perl

use strict;
use warnings;

use Net::Nmsg::Input;
use Data::Dumper;


{
  package Encode;

  sub new {
    my $class = shift;
    my($enc, $dec) = @_ ? @_ : (sub { $_[0] }, sub { $_[0] });
    bless { _encode => $enc, _decode => $dec }, $class;
  }

  sub encode { my $self = shift; $self->{_encode}->(@_) }

  sub decode { my $self = shift; $self->{_decode}->(@_) }

}

my %Encoders;

$Encoders{TEXT} = Encode->new;

eval "use JSON qw()";
$Encoders{JSON} = $@ ? 0 :
  Encode->new(\&JSON::encode_json, \&JSON::decode_json);

eval "use YAML qw()";
$Encoders{YAML} = $@ ? 0 : 
  Encode->new(\&YAML::Dump, \&YAML::Load); 
eval "use Data::MessagePack";
$Encoders{MSGPACK} = $@ ? 0 :
  Encode->new(
    sub { Data::MessagePack->pack(@_) },
    sub { Data::MessagePack->unpack(@_) },
  );

eval "use XML::Dumper";
if ($@) {
  $Encoders{XML} = 0;
}
else {
  my $xdump = XML::Dumper->new;
  $Encoders{XML} = Encode->new(
    sub { $xdump->pl2xml(@_) },
    sub { $xdump->xml2pl(@_) },
  );
}
 
sub process {
  my $m = shift;
  print STDERR $m->headers_as_str, "\n";
  my $type = $m->get_type;
  my $enc  = $Encoders{$type};
  print STDERR "type: ", $m->get_type, "\n";
  if ($enc) {
    print STDERR "payload: ", Dumper($enc->decode($m->get_payload));
  }
  elsif (defined $enc) {
    print STDERR "payload: <UNABLE TO DECODE>\n";
  }
  else {
    print STDERR "payload: <UNKNOWN ENCODING>\n";
  }
  print STDERR "\n\n";
}

my($addr, $port) = @_;
if (! defined $addr) {
  ($addr, $port) = ('127.0.0.1', 9430);
}
else {
  print STDERR "Usage: $0 [<ADDR> <PORT>]\n";
  exit 1;
}

my $i = Net::Nmsg::Input->open_sock($addr, $port);
print STDERR "listening on $addr/$port\n";

while (1) {
  process($i->read() || next);
}
