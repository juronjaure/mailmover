#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::DkCommon;
use base "Mail::DKIM::Canonicalization::Base";
use Carp;

sub add_header
{
	my $self = shift;
	my ($line) = @_;

	#croak "header parse error \"$line\"" unless ($line =~ /:/);

	if ($line =~ /^domainkey-signature:/i)
	{
		# DomainKeys never includes headers that precede the
		# DomainKey-Signature header
		$self->{myheaders} = [];
	}
	else
	{
		push @{$self->{myheaders}}, $self->canonicalize_header($line);
	}
}

sub finish_header
{
	my $self = shift;

	# check if signature specifies a list of headers
	my @sigheaders = $self->{Signature}->headerlist;

	# iterate through each header, in the same order they appear in
	# the message
	foreach my $line (@{$self->{myheaders}})
	{
		if (@sigheaders)
		{
			# if signature specifies a list of headers, we filter the
			# canonicalized headers according to headers that are named
			# in the signature

			my $field_name = "";
			if ($line =~ /^([^\s:]+)\s*:/)
			{
				$field_name = lc $1;
			}
			next unless (grep {lc($_) eq $field_name} @sigheaders);
		}
		$self->output($line);
	}

	$self->output($self->canonicalize_body("\015\012"));
}

sub add_body
{
	my $self = shift;
	my ($line) = @_;

	$self->output($self->canonicalize_body($line));
}

sub finish_body
{
}

sub finish_message
{
}

1;
