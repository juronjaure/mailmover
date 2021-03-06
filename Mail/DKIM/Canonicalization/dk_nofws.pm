#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::dk_nofws;
use base "Mail::DKIM::Canonicalization::dk_simple";
use Carp;

sub canonicalize_header
{
	my $self = shift;
	my ($line) = @_;

	$line =~ s/[\t\n\r\ ]//g;
	return $self->SUPER::canonicalize_header($line . "\015\012");
}

sub canonicalize_body
{
	my $self = shift;
	my ($line) = @_;

	$line =~ s/[\t\n\r\ ]//g;
	return $self->SUPER::canonicalize_body($line . "\015\012");
}

1;
