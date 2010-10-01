use Test::More tests => 7;

use FindBin;
use lib $FindBin::Bin;

BEGIN {
  use_ok('Net::Nmsg');
  use_ok('nmsgtest');
}

use_ok(UTIL_CLASS);
use_ok(IO_CLASS);
use_ok(INPUT_CLASS);
use_ok(OUTPUT_CLASS);
use_ok(MSG_CLASS);
