#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::PublicKey;

use base ("Mail::DKIM::KeyValueList", "Mail::DKIM::Key");
*calculate_EM = \&Mail::DKIM::Key::calculate_EM;

use Mail::DKIM::DNS;

sub new {
	my $type = shift;
	my %prms = @_;

	my $self = {};

	$self->{'GRAN'} = $prms{'Granularity'};
	$self->{'NOTE'} = $prms{'Note'};
	$self->{'TEST'} = $prms{'Testing'};
	$self->{'TYPE'} = ($prms{'Type'} or "rsa");
	$self->{'DATA'} = $prms{'Data'};

	bless $self, $type;
}

# my $public_key = Mail::DKIM::PublicKey->fetch(
#                     Protocol => "dns",
#                   );
# Protocol: from the q= tag of the signature, usually "dns"
# Selector: from the s= tag of the signature
# Domain: from the d= tag of the signature
#
sub fetch
{
	my $class = shift;
	my %prms = @_;

	my $strn;


	my ($query_type, $query_options) = split(/\//, $prms{Protocol}, 2);
	if (lc($query_type) ne "dns")
	{
		die "unknown query type '$query_type'\n";
	}

	my $host = $prms{'Selector'} . "._domainkey." . $prms{'Domain'};

	#
	# perform DNS query for public key...
	#   if the query takes too long, we should generate an error
	#
	my $resp = Mail::DKIM::DNS::query($host, "TXT");
	unless ($resp)
	{
		# no response => NXDOMAIN
		return;
	}

	foreach my $ans ($resp->answer) {
		next unless $ans->type eq "TXT";
		$strn = join "", $ans->char_str_list;
	}

	$strn or
		return;

	my $self = $class->parse($strn);
	$self->{Selector} = $prms{'Selector'};
	$self->{Domain} = $prms{'Domain'};
	$self->check;
	return $self;
}

# check syntax of the public key
# throw an error if any errors are detected
sub check
{
	my $self = shift;

	# check public key version tag
	if (my $v = $self->get_tag("v"))
	{
		unless ($v eq "DKIM1")
		{
			die "unrecognized public key version\n";
		}
	}

	# check public key granularity
	my $g = $self->granularity;

	# check key type
	if (my $k = $self->get_tag("k"))
	{
		unless ($k eq "rsa")
		{
			die "public key: unsupported key type\n";
		}
	}

	# check public-key data
	my $p = $self->data;
	if (not defined $p)
	{
		die "public key: missing p= tag\n";
	}
	if ($p eq "")
	{
		die "public key: revoked\n";
	}
	unless ($p =~ /^[A-Za-z0-9\+\/\=]+$/)
	{
		die "public key: invalid data\n";
	}

	# have OpenSSL load the key
	eval
	{
		$self->cork;
	};
	if ($@)
	{
		# see also finish_body
		chomp (my $E = $@);
		if ($E =~ /(OpenSSL error: .*?) at /)
		{
			$E = "public key: $1";
		}
		elsif ($E =~ /^(panic:.*?) at /)
		{
			$E = "public key: OpenSSL $1";
		}
		die "$E\n";
	}

	# check service type
	if (my $s = $self->get_tag("s"))
	{
		my @list = split(/:/, $s);
		unless (grep { $_ eq "*" || $_ eq "email" } @list)
		{
			die "public key: does not support email\n";
		}
	}

	return 1;
}

sub check_hash_algorithm
{
	my $self = shift;
	my ($hash_algorithm) = @_;

	# check hash algorithm
	if (my $h = $self->get_tag("h"))
	{
		my @list = split(/:/, $h);
		unless (grep { $_ eq $hash_algorithm } @list)
		{
			die "public key: does not support hash algorithm '$hash_algorithm'\n";
		}
	}
	return 1;
}

# Create an OpenSSL public key object from the Base64-encoded data
# found in this public key's DNS record. The OpenSSL object is saved
# in the "cork" property.
sub convert
{
	use Crypt::OpenSSL::RSA;

	my $self = shift;


	$self->data or
		return;

	# have to PKCS1ify the pubkey because openssl is too finicky...
	my $cert = "-----BEGIN PUBLIC KEY-----\n";

	for (my $i = 0; $i < length $self->data; $i += 64) {
		$cert .= substr $self->data, $i, 64;
		$cert .= "\n";
	}	

	$cert .= "-----END PUBLIC KEY-----\n";

	my $cork = Crypt::OpenSSL::RSA->new_public_key($cert)
		or die "unable to generate public key object";

	# segfaults on my machine
#	$cork->check_key or
#		return;

	$self->cork($cork);

	return 1;
}

sub verify {
	my $self = shift;
	my %prms = @_;


	my $rtrn;

	eval {
		$rtrn = $self->cork->verify($prms{'Text'}, $prms{'Signature'});
	}; 

	$@ and
		$self->errorstr($@),
		return;
	
	return $rtrn;
}

sub granularity
{
	my $self = shift;

	(@_) and 
		$self->set_tag("g", shift);

	return $self->get_tag("g");
}

sub notes
{
	my $self = shift;

	(@_) and 
		$self->set_tag("n", shift);

	return $self->get_tag("n");
}

sub data
{
	my $self = shift;

	(@_) and 
		$self->set_tag("p", shift);

	my $p = $self->get_tag("p");
	# remove whitespace (actually only LWSP is allowed)
	$p =~ tr/\015\012 \t//d  if defined $p;
	return $p;
}

sub flags
{
	my $self = shift;

	(@_) and 
		$self->set_tag("t", shift);

	return $self->get_tag("t");
}

sub revoked
{
	my $self = shift;

	$self->data or
		return 1;

	return;
}

sub testing
{
	my $self = shift;

	my $flags = $self->flags;
	my @flaglist = split(/:/, $flags);
	if (grep { $_ eq "y" } @flaglist)
	{
		return 1;
	}
	return undef;
}

sub verify_sha1_digest
{
	my $self = shift;
	my ($digest, $signature) = @_;
	return $self->verify_digest("SHA-1", $digest, $signature);
}

sub verify_digest
{
	my $self = shift;
	my ($digest_algorithm, $digest, $signature) = @_;

	my $rsa_pub = $self->cork;
	if (!$rsa_pub) {
		$@ = $@ ne '' ? "RSA failed: $@" : "RSA unknown problem";
		$@ .= ", s=$self->{Selector} d=$self->{Domain}";
		return;
	}

	$rsa_pub->use_no_padding;
	my $verify_result = $rsa_pub->encrypt($signature);

	my $k = $rsa_pub->size;
	my $expected = calculate_EM($digest_algorithm, $digest, $k);
	return 1 if ($verify_result eq $expected);

	# well, the RSA verification failed; I wonder if the RSA signing
	# was performed on a different digest value? I think we can check...

	# basically, if the $verify_result has the same prefix as $expected,
	# then only the digest was different

	my $digest_len = length $digest;
	my $prefix_len = length($expected) - $digest_len;
	if (substr($verify_result, 0, $prefix_len)
		eq substr($expected, 0, $prefix_len))
	{
		$@ = "message has been altered";
		return;
	}

	$@ = "bad RSA signature";
	return;
}

1;
