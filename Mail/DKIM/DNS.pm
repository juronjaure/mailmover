#!/usr/bin/perl

# Copyright 2007 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

use strict;
use warnings;

# this class contains a method to perform asynchronous DNS queries

package Mail::DKIM::DNS;
use Net::DNS;

sub query
{
	my ($domain, $type) = @_;

	my $rslv = Net::DNS::Resolver->new()
		or die "can't create DNS resolver";

	#
	# perform the DNS query
	#   if the query takes too long, we should generate an error
	#
	my $resp;
	eval
	{
		# set a 10 second timeout
		local $SIG{ALRM} = sub { die "DNS query timeout for $domain\n" };
		alarm 10;

		# the query itself could cause an exception, which would prevent
		# us from resetting the alarm before leaving the eval {} block
		# so we wrap the query in a nested eval {} block
		eval
		{
			$resp = $rslv->query($domain, $type);
		};
		my $E = $@;
		alarm 0;
		die $E if $E;
	};
	my $E = $@;
	alarm 0; #FIXME- restore previous alarm?
	die $E if $E;

	return $resp;
}

1;
