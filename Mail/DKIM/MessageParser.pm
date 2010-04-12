#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::MessageParser;
use Carp;

sub new_object
{
	my $class = shift;
	return $class->TIEHANDLE(@_);
}

sub new_handle
{
	my $class = shift;
	local *TMP;
	tie *TMP, $class, @_;
	return *TMP;
}

sub TIEHANDLE
{
	my $class = shift;
	my %args = @_;
	my $self = bless \%args, $class;
	$self->init;
	return $self;
}

sub init
{
	my $self = shift;

	$self->{in_header} = 1;
	$self->{buf} = "";
}

sub PRINT
{
	my $self = shift;
	my $buf = $self->{buf} . join("", @_);

	while (length $buf)
	{
		if ($self->{in_header} && $buf =~ /^\015\012/s)
		{
			$buf = substr($buf, 2);
			$self->finish_header();
			$self->{in_header} = 0;
			next;
		}
		elsif ($self->{in_header} && $buf =~ /^(.*?\015\012)[^\ \t]/s)
		{
			my $header = $1;
			$buf = substr($buf, length($header));
			$self->add_header($header);
			next;
		}
		elsif (!$self->{in_header} && $buf =~ /^(.*?\015\012)/s)
		{
			my $body_line = $1;
			$buf = substr($buf, length($body_line));
			$self->add_body($body_line);
			next;
		}
		last;
	}
	$self->{buf} = $buf;
}

sub CLOSE
{
	my $self = shift;
	my $buf = $self->{buf};

	if ($self->{in_header})
	{
		if (length $buf)
		{
			# A line of header text ending CRLF would not have been
			# processed yet since before we couldn't tell if it was
			# the complete header. Now that we're in CLOSE, we can
			# finish the header...
			$buf =~ s/\015\012$//s;
			$self->add_header("$buf\015\012");
		}
		$self->finish_header;
		$self->{in_header} = 0;
	}
	else
	{
		if (length $buf)
		{
			$self->add_body($buf);
		}
	}
	$self->{buf} = "";
	$self->finish_body;
}

sub add_header
{
	die "not implemented";
}

sub finish_header
{
	die "not implemented";
}

sub add_body
{
	die "not implemented";
}

sub finish_body
{
	# do nothing by default
}

sub reset
{
	carp "reset not implemented";
}

1;
