#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::relaxed;
use base "Mail::DKIM::Canonicalization::DkimCommon";
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

	#
	# step 1: convert all header field names (not the header field values)
	# to lower case
	#
	if ($line =~ /^([^:]+):(.*)/s)
	{
		# lowercase field name
		$line = lc($1) . ":$2";
	}

	#
	# step 2: unwrap all header field continuation lines... i.e.
	# remove any CRLF sequences that are followed by WSP
	#
	$line =~ s/\015\012(\s)/$1/g;

	#
	# step 3: convert all sequences of one or more WSP characters to
	# a single SP character
	#
	$line =~ s/[ \t]+/ /g;

	#
	# step 4: delete all WSP characters at the end of the header field value
	#
	$line =~ s/ \z//s;

	# 
	# step 5: delete any WSP character remaining before and after the colon
	# separating the header field name from the header field value
	#
	$line =~ s/^([^:\s]+)\s*:\s*/$1:/;

	return $line;
}

sub canonicalize_body
{
	my $self = shift;
	my ($line) = @_;

	$line =~ s/\015\012\z//s;

	#
	# step 1: ignore all white space at the end of lines
	#
	$line =~ s/[ \t]+$//;

	#
	# step 2: reduce all sequences of WSP within a line to a single
	# SP character
	#
	$line =~ s/[ \t]+/ /g;

	$line .= "\015\012";

	#
	# step 3: ignore empty lines at the end of the message bode
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
