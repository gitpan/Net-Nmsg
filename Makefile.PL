use 5.004_04;
use ExtUtils::MakeMaker;

my @libs = map { "-l$_" } ( NMSG_LIB_NAME, PCAP_LIB_NAME );

my %opt = (
  NAME          => 'Net::Nmsg',
  LIBS          => ['-lnmsg -lpcap'],
  INC           => "-I.",
  VERSION_FROM  => 'lib/Net/Nmsg.pm',
  ABSTRACT_FROM => 'lib/Net/Nmsg.pm',
  AUTHOR        => 'Matt Sisk <sisk@cert.org>',
  PREREQ_PM => {
    'Math::Int64'       => 0,
    'NetAddr::IP::Util' => 0,
  },
);

WriteMakefile(%opt);
