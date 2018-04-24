#!/usr/bin/perl

##########################################################################
# Author: Lucas Thoresen                                                 #
# Attribution: cleen -> http://www.perlmonks.org/index.pl?node_id=17576  #
# Date: December 8, 2012                                                 #
# Purpose: To demonstrate Perl UDP packet generation.                    #
#          Hopefully someone will find this useful. :]                   #
##########################################################################

use strict;
use warnings;
use Socket;

# Source and destination IP/Hostname
my $ip_src = (gethostbyname($ARGV[0]))[4];
my $ip_dst = (gethostbyname($ARGV[1]))[4];

# Check to see if all parameters are present
if (!defined $ip_src or !defined $ip_dst) {
    exit "Usage: $0 <source ip> <destination ip>\n";
}

# Setup the socket to be used 255 is IPPROTO_RAW)
socket(RAW, AF_INET, SOCK_RAW, 255) or die $!;
setsockopt(RAW, 0, 1, 1);

main();

# Main program
sub main {
    my $packet;

    # Add the layer 3 and 4 headers
    $packet = ip_header();
    $packet .= udp_header();

    # Add in a data section
    $packet .= payload();

    # Fire!
    send_packet($packet);
}

# Builds an IP header (Layer 3)
sub ip_header {
    my $ip_ver         = 4;                    # IP Version 4            (4 bits)
    my $ip_header_len  = 5;                    # IP Header Length        (4 bits)
    my $ip_tos         = 0;                    # Differentiated Services (8 bits)
    my $ip_total_len   = $ip_header_len + 20;  # IP Header Length + Data (16 bits)
    my $ip_frag_id     = 0;                    # Identification Field    (16 bits)
    my $ip_frag_flag   = '000';                # IP Frag Flags (R DF MF) (3 bits)
    my $ip_frag_offset = '0000000000000';      # IP Fragment Offset      (13 bits)
    my $ip_ttl         = 255;                  # IP TTL                  (8 bits)
    my $ip_proto       = 17;                   # IP Protocol             (8 bits)
    my $ip_checksum    = 0;                    # IP Checksum             (16 bits)

    my $ip_header = pack(
        'H2 H2 n n B16 h2 c n a4 a4',
        $ip_ver . $ip_header_len, $ip_tos, $ip_total_len,
        $ip_frag_id, $ip_frag_flag . $ip_frag_offset,
        $ip_ttl, $ip_proto, $ip_checksum,
        $ip_src,
        $ip_dst
    );

    return $ip_header;
}

# Builds a UDP header (Layer 4)
sub udp_header {
    my $udp_src_port = 60;                     # UDP Sort Port           (16 bits)
    my $udp_dst_port = 60;                     # UDP Dest Port           (16 btis)
    my $udp_len      = 8 + length(payload());  # UDP Length              (16 bits)
    my $udp_checksum = 0;                      # UDP Checksum            (16 bits)

    my $udp_header = pack(
        'n n n n',
        $udp_src_port, $udp_dst_port,
        $udp_len, $udp_checksum
    );

    return $udp_header;
}

# Builds a data section
sub payload {
    my $data = 'abcdefghijklmnopqrstuvwxyz hi';

    # Pack the data in dynamically
    my $payload = pack(
        'a' . length($data), $data
    );

    return $payload;
}

# Send the packet
sub send_packet {
    # @_ doesn't work, you need to use $_[0] as the param to the send sub!
    send(RAW, $_[0], 0, pack('Sna4x8', AF_INET, 60, $ip_dst));
}

# Todo: Reliably calculate checksum using 'pseudo headers'
sub checksum {}
