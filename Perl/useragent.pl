#!usr/bin/perl -w
# UserAgent example using LWP::UserAgent module
use strict;
use LWP::UserAgent;

my $ua = LWP::UserAgent->new;
$ua->agent('Mozilla/5.0 (Windows; U; Windows NT 6.1 en-US; rv:1.9.2.18)Gecko/20110614 Firefox/3.6.18');


# Enter a URL on the command line and shift pops it off
my $req = HTTP::Request->new(GET => shift);
my $res = $ua->request($req);

# Split by newlines
my @lines = split(/\n/,$res->content);
die "URL cannot be reached!" unless $res->code == 200;
foreach(@lines){
print $_."\n" if($_=~ m/<img.+src=("|').*>/);
}

