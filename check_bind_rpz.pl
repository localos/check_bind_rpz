#!/usr/bin/env perl -w

#####################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#####################################################


#####################################################
#
# Script for checking bind RPZ logfile (rpz.log),
# for suspicious/blacklisted queries/domains
#
# Author: solacol
# Version: 0.1
#
#####################################################
#
#
# TODO:
# - something with th warn level, makes currently no sense
#
# CHANGE-LOG:
# - init
#
###

use strict;
use warnings;

my $logfile = $ARGV[0];
my $time_period = $ARGV[1];
my $warn_thres = $ARGV[2];
my $mode = $ARGV[3];
my %h_queries = ();
my @a_results_critical = ();
my @a_results_warn = ();

my %h_errors = (
	'OK' => 0,
	'WARNING' => 1,
	'CRITICAL'=> 2,
	'UNKNOWN' => 3
	);

# Check if mandatory arguments are given and defined
die("HELP: scriptname logfile [check_period in hours] [warning_threshold] [quiet|verbose]") unless(defined($logfile));

# Set time period for checking to 24h if not given
$time_period = 24 unless(defined($time_period) && $time_period =~ m/[[:digit:]]/);

# Set warning threshold to 5 if not given
$warn_thres = 5 unless(defined($warn_thres) && $warn_thres =~ m/[[:digit:]]/);

# Set mode to quiet if not given
$mode = 'quiet' unless(defined($mode) && ($mode eq 'quiet' || $mode eq 'verbose'));

# Get current time and set it according to time period to check (in epoch)
my $current_date = `/bin/date \+\%s`;
my $check_period = `/bin/date \+\%s \-d \"\- $time_period hours\"`;

# Grep all lines of logfile ... this could also be done with readin/while ... but not on my system ;-)
my @a_logfile = `/usr/bin/sudo /bin/grep \\.\\* $logfile`;

foreach my $line (@a_logfile){
	chomp($line);
	# Skip if not starting with right keywords
	next if($line !~ m/^(.*)\sclient\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\#.*\(([a-zA-Z0-9\.-]+)\)\:/);
    my $full_query = $line;
	# Compare timestamp to check period and skip if to old
	my $timestamp = `date \-d \"$1\" \+\%s`;
	chomp($timestamp);
	next if($timestamp <= $check_period);
    my $ip = $2;
	my $query = $3;
	chomp($query);

	if(exists $h_queries{$query}){
        my $ref_h_ips = $h_queries{$query};

	    unless(exists $$ref_h_ips{$ip}){
            $$ref_h_ips{$ip} = $full_query;
        }

		next;
	}
	else{
        my %ref_h_ips = ();
        $ref_h_ips{$ip} = $full_query;
		$h_queries{$query} = \%ref_h_ips;
	}
}

# All relevant hash entries to array
foreach my $query (keys %h_queries){
    my $ref_h_ips = $h_queries{$query};
    my $string = $query;

    foreach my $ip (keys %$ref_h_ips){
        $string = $string.'|'.$ip;
    }

	push(@a_results_critical,"$string");
}

# State check and array elements to string
if(scalar(@a_results_critical) > 0){
	my $result = 'CRIT - '.scalar(@a_results_critical).' Blacklisted Domain (use verbose mode immediately)';
	if($mode eq 'verbose'){
		$result = join("\n",@a_results_critical);
		$result = $result."\n";
	}
	print("$result");
	exit($h_errors{'CRITICAL'});
}
elsif(scalar(@a_results_warn) > 0){
	my $result = 'WARN - '.scalar(@a_results_warn).' IPs are suspicious (use verbose mode)';
	if($mode eq 'verbose'){
		$result = join("\n",@a_results_warn);
                $result = $result."\n";
	}
	print("$result");
	exit($h_errors{'WARNING'});
}
else{
	my $result = "Seems to be fine for the last $time_period hours ... at least according to $logfile";
	if($mode eq 'verbose'){
		$result = $result."\n";
	}
	print("$result");
	exit($h_errors{'OK'});
}
