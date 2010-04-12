#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::dk_simple;
use base "Mail::DKIM::Canonicalization::DkCommon";
use Carp;

sub init
{
	my $self = shift;
	$self->SUPER::init;

	$self->{canonicalize_body_buf} = "";
}

sub canonicalize_header
{
	my $self = shift;
	croak "wrong number of parameters" unless (@_ == 1);
	my ($line) = @_;

	return $line;
}

sub canonicalize_body
{
	my $self = shift;
	my ($line) = @_;

	# ignore empty lines at the end of the message body

	#
	# (i.e. do not emit empty lines until a following nonempty line
	# is found)
	#
	if ($line eq "\015\012")
	{
		$self->{canonicalize_body_buf} .= $line;
		$line = "";
	}
	else
	{
		$line = $self->{canonicalize_body_buf} . $line;
		$self->{canonicalize_body_buf} = "";
	}

	return $line;
}

1;
