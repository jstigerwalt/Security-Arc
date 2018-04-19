#!/usr/bin/perl -w

use strict;
use XtraType;
use Net::PcapUtils;
use NetPacket::Ethernet qw( :types :strip );
use NetPacket::IP;

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

our $num_packets;

our %src_hosts = ();
our %dest_hosts = ();
our %e2ip = ();


sub got_a_packet {
    my $packet = shift;

    my $frame = NetPacket::Ethernet->decode($packet);

    if ($frame->{type} < 1501) {
        $type_totals{1500}++;
    } else {
        $type_totals{ $frame->{type} }++;
    }
    
    $src_hosts{$frame->{src_mac}}++;
    $dest_hosts{$frame->{dest_mac}}++;
    
    if ($frame->{type} == NetPacket::Ethernet::ETH_TYPE_IP) {
        my $ip_datagram = NetPacket::IP->decode(NetPacket::Ethernet::eth_strip($packet));
        
        $e2ip{$frame->{src_mac}} = $ip_datagram->{src_ip};
        $e2ip{$frame->{dest_mac}} = $ip_datagram->{dest_ip};
    }
    
    $num_packets++;
    }


sub display_results {
    print "$num_packets frames processed\n\n";
    
    # Packet Count by Type, uses hash with hex to compare with frame header.
    # Need to add my types of packets. 
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
    
    # Host Stats
    print "The host statistics are:\n\nSources:\n\n";
    foreach my $host (sort keys %src_hosts) {
        if (exists $e2ip{$host}) {
            print "Host: $host ($e2ip{$host}), ";
            print "Count: $src_hosts{$host}\n";
        } else {
            print "Host: $host, Count: $src_hosts{$host}\n";
        }
    }
    
    print "\nDestinations\n\n";
    foreach my $host (sort keys %dest_hosts) {
        if (exists $e2ip{$host}) {
            print "Host: $host ($e2ip{$host}), ";
            print "Count: $dest_hosts{$host}\n";
        } else {
            print "Host: $host, Count: $dest_hosts{$host}\n";
        }
    }
    
    # Raw Packet types
    print "\nRaw stats:\n\n";
    print "frame-type -> frequency\n\n";
    foreach my $e_total ( sort keys %type_totals ) {
        printf "%lx -> %d\n", $e_total, $type_totals{$e_total};
    }
    
}


my $pkt_descriptor = Net::PcapUtils::open;

if ( !ref( $pkt_descriptor ) ) {
    print "Net::PcapUtils::open returned: $pkt_descriptor\n";
    exit;
    }
    
my $minute = 3;
my $now = time;
my $then = $now + (60 * $minute);

my ($next_packet, %next_header);

while (($now = time) < $then) {
    ($next_packet, %next_header) = Net::PcapUtils::next($pkt_descriptor);
    got_a_packet($next_packet);
}

display_results();
