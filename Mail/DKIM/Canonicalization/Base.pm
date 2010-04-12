#!/usr/bin/perl

# Copyright 2005 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::Canonicalization::Base;
use base "Mail::DKIM::MessageParser";
use Carp;

sub new
{
	my $class = shift;
	return $class->new_object(@_);
}

sub init
{
	my $self = shift;
	$self->SUPER::init;

	unless ($self->{output} || $self->{output_fh} || $self->{output_digest}
		|| $self->{buffer})
	{
		$self->{result} = "";
		$self->{buffer} = \$self->{result};
	}
}

sub output
{
	my $self = shift;
	my ($output) = @_;

	my $out_fh = $self->{output_fh};
	if ($out_fh)
	{
		print $out_fh $output;
	}
	if (my $digest = $self->{output_digest})
	{
		$digest->add($output);
	}
	if (my $out_obj = $self->{output})
	{
		$out_obj->PRINT($output);
	}
	if (my $buffer = $self->{buffer})
	{
		${$self->{buffer}} .= $output;
	}

	# this supports Debug_Canonicalization
	if (my $debug = $self->{Debug_Canonicalization})
	{
		if (UNIVERSAL::isa($debug, "SCALAR"))
		{
			$$debug .= $output;
		}
		elsif (UNIVERSAL::isa($debug, "GLOB"))
		{
			print $debug $output;
		}
		elsif (UNIVERSAL::isa($debug, "IO::Handle"))
		{
			$debug->print($output);
		}
	}
}

sub result
{
	my $self = shift;
	return $self->{result};
}

1;

__END__

=head1 NAME

Mail::DKIM::Canonicalization::Base - base class for canonicalization methods

=head1 SYNOPSIS

  # canonicalization results get output to STDOUT
  my $method = new Mail::DKIM::Canonicalization::relaxed(
                    output_fh => *STDOUT,
                    Signature => $dkim_signature);

  # add headers
  $method->add_header("Subject: this is the subject\015\012");
  $method->finish_header;

  # add body
  $method->add_body("This is the body.\015\012");
  $method->add_body("Another line of the body.\015\012");
  $method->finish_body;

  # this adds the signature to the end
  $method->finish_message;

=head1 CONSTRUCTOR

Use the new() method of the desired canonicalization implementation class
to construct a canonicalization object. E.g.

  my $method = new Mail::DKIM::Canonicalization::relaxed(
                    output_fh => *STDOUT,
                    Signature => $dkim_signature);

The constructors accept these arguments:

=over

=item Signature

(Required) Provide the DKIM signature being constructed (if the message is
being signed), or the DKIM signature being verified (if the message is
being verified). The canonicalization method either writes parameters to
the signature, or reads parameters from the signature (e.g. the h= tag).

=item output

If specified, the canonicalized message will be passed to this object with
the PRINT method.

=item output_digest

If specified, the canonicalized message will be added to this digest.
(Uses the add() method.)

=item output_fh

If specified, the canonicalized message will be written to this file
handle.

=back

If none of the output parameters are specified, then the canonicalized
message is appended to an internal buffer. The contents of this buffer
can be accessed using the result() method.

=head1 METHODS

=head2 add_body() - feeds part of the body into the canonicalization

  $method->add_body("This is the body.\015\012");
  $method->add_body("Another line of the body.\015\012");

The body should be fed one "line" at a time.

=head2 result()

  my $result = $method->result;

If you did not specify an object or handle to send the output to, the
result of the canonicalization is stored in the canonicalization method
itself, and can be accessed using this method.

=cut
