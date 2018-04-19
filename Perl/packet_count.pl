#!/usr/bin/perl -w

# Change the count number to lower number for smaller network. 
# Will display Hex vaule of type. Check custom XtraType module on my GitHub.

use strict;
use Net::PcapUtils;
use NetPacket::Ethernet qw( :types );
use XtraType;

our $num_packets;

our %type_totals = ();

our %type_desc = (
    0x0800 => 'IPv4',
    0x0806 => 'ARP',
    0x809B => 'AppleTalk',
    0x814C => 'SNMP',
    0x86DD => 'IPv6',
    0x880B => 'PPP',
    0x8137 => 'NOVELL1',
    0x8138 => 'NOVELL2',
    0x8035 => 'RARP',
    0x876B => 'TCP/IPc'
    );

sub got_a_packet {
    my ( $user_arg, $header, $packet ) = @_;

    my $frame = NetPacket::Ethernet->decode( $packet );

    if ($frame->{type} < 1501) {
        $type_totals{1500}++;
    } else {
        $type_totals{ $frame->{type} }++;
    }
        
    $num_packets++;
    }

my $status = Net::PcapUtils::loop(
                \&got_a_packet,
                NUMPACKETS => 100000
            );

if ( $status ) {
    print "Net::PcapUtils::loop returned: $status\n";
    } else {
    display_results();
}

sub display_results {
    print "$num_packets frames processed\n\n";

    foreach my $etype ( sort keys %type_desc ) {
        print "$type_desc{$etype} generated ";
        if ( exists $type_totals{$etype} ) {
            print "$type_totals{$etype} packets.\n";
        } else {
            print "No Packets.\n";
        }
    }
    print "\nNon Ethernet II (DIX) frames generated";
    print " $type_totals{1500} packets. \n";
    
    print "\nRaw stats:\n\n";
    print "frame-type -> frequency\n\n";
    foreach my $e_total ( sort keys %type_totals ) {
        printf "%lx -> %d\n", $e_total, $type_totals{$e_total};
    }
    
}







