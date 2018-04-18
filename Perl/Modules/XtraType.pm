package XtraType;
#
# XtraType.pm - Some additional Ethernet frame types.
#
use 5.6.0;
require Exporter;
our @ISA = qw( Exporter );
# We export all the symbols declared in this module by
# default.
our @EXPORT = qw(
ETH_TYPE_NOVELL1
ETH_TYPE_NOVELL2
ETH_TYPE_TCP_IP_COMPRESSION
);
our @EXPORT_OK = qw(
);
our %EXPORT_TAGS = (
);
our $VERSION = 0.01;
use constant ETH_TYPE_NOVELL1 => 0x8137;
use constant ETH_TYPE_NOVELL2 => 0x8138;
use constant ETH_TYPE_TCP_IP_COMPRESSION => 0x876B;
1;
