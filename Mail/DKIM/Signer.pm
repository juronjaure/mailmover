#!/usr/bin/perl

# Copyright 2005-2007 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Algorithm::rsa_sha1;
use Mail::DKIM::Signature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Signer - generates a DKIM signature for a message

=head1 SYNOPSIS

  use Mail::DKIM::Signer;

  # create a signer object
  my $dkim = Mail::DKIM::Signer->new(
                  Algorithm => "rsa-sha1",
                  Method => "relaxed",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key");
             );

  # read an email from a file handle
  $dkim->load(*STDIN);

  # or read an email and pass it into the signer, one line at a time
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the signature result?
  my $signature = $dkim->signature;

=head1 CONSTRUCTOR

=head2 new() - construct an object-oriented signer

  # create a signer using the default policy
  my $dkim = Mail::DKIM::Signer->new(
                  Algorithm => "rsa-sha1",
                  Method => "relaxed",
                  Domain => "example.org",
                  Selector => "selector1",
                  KeyFile => "private.key",
             );

  # create a signer using a custom policy
  my $dkim = Mail::DKIM::Signer->new(
                  Policy => $policyfn,
                  KeyFile => "private.key",
             );

You must always specify the name of a private key file. In addition,
you must specify a policy object, or specify the algorithm, method,
domain, and selector to use. Use of the policy object lets you defer
the determination of algorithm, method, domain and selector until
the message being signed has been partially read.

See Mail::DKIM::SignerPolicy for more information about policy objects.

=cut

package Mail::DKIM::Signer;
use base "Mail::DKIM::Common";
use Carp;
our $VERSION = '0.28';

# PROPERTIES
#
# public:
#
# $dkim->{Algorithm}
#   identifies what algorithm to use when signing the message
#   default is "rsa-sha1"
#
# $dkim->{Domain}
#   identifies what domain the message is signed for
#
# $dkim->{KeyFile}
#   name of the file containing the private key used to sign
#
# $dkim->{Method}
#   identifies what canonicalization method to use when signing
#   the message. default is "relaxed"
#
# $dkim->{Policy}
#   a signing policy (of type Mail::DKIM::SigningPolicy)
#
# $dkim->{Selector}
#   identifies name of the selector identifying the key
#
# private:
#
# $dkim->{algorithms} = []
#   an array of algorithm objects... an algorithm object is created for
#   each signature being added to the message
#
# $dkim->{private}
#   the loaded private key
#
# $dkim->{result}
#   result of the signing policy: "signed" or "skipped"
#
# $dkim->{signature}
#   the created signature (of type Mail::DKIM::Signature)


sub init
{
	my $self = shift;
	$self->SUPER::init;

	if (defined $self->{KeyFile})
	{
		croak "not a file: " . $self->{KeyFile}
			unless (-f $self->{KeyFile});

		$self->{private} = Mail::DKIM::PrivateKey->load(
				File => $self->{KeyFile});
	}
	croak "No private key specified"
		unless ($self->{private});
	
	unless ($self->{"Algorithm"})
	{
		# use default algorithm
		$self->{"Algorithm"} = "rsa-sha1";
	}
	unless ($self->{"Method"})
	{
		# use default canonicalization method
		$self->{"Method"} = "relaxed";
	}
	unless ($self->{"Domain"})
	{
		# use default domain
		$self->{"Domain"} = "example.org";
	}
	unless ($self->{"Selector"})
	{
		# use default selector
		$self->{"Selector"} = "unknown";
	}
}

sub finish_header
{
	my $self = shift;

	$self->{algorithms} = [];

	my $policy = $self->{Policy};
	if (UNIVERSAL::isa($policy, "CODE"))
	{
		# policy is a subroutine ref
		my $default_sig = $policy->($self);
		unless (@{$self->{algorithms}} || $default_sig)
		{
			$self->{"result"} = "skipped";
			return;
		}
	}
	elsif ($policy && $policy->can("apply"))
	{
		# policy is a Perl object or class
		my $default_sig = $policy->apply($self);
		unless (@{$self->{algorithms}} || $default_sig)
		{
			$self->{"result"} = "skipped";
			return;
		}
	}

	unless (@{$self->{algorithms}})
	{
		# no algorithms were created yet, so construct a signature
		# using the current signature properties

		# check properties
		unless ($self->{"Algorithm"})
		{
			die "invalid algorithm property";
		}
		unless ($self->{"Method"})
		{
			die "invalid method property";
		}
		unless ($self->{"Domain"})
		{
			die "invalid header property";
		}
		unless ($self->{"Selector"})
		{
			die "invalid selector property";
		}

		$self->add_signature(
			new Mail::DKIM::Signature(
				Algorithm => $self->{"Algorithm"},
				Method => $self->{"Method"},
				Headers => $self->headers,
				Domain => $self->{"Domain"},
				Selector => $self->{"Selector"},
			));
	}

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# output header as received so far into canonicalization
		foreach my $header (@{$self->{headers}})
		{
			$algorithm->add_header($header);
		}
		$algorithm->finish_header;
	}
}

sub finish_body
{
	my $self = shift;

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# finished canonicalizing
		$algorithm->finish_body;

		# compute signature value
		my $signb64 = $algorithm->sign($self->{private});
		$algorithm->signature->data($signb64);

		# insert linebreaks in signature data, if desired
		$algorithm->signature->prettify_safe();

		$self->{signature} = $algorithm->signature;
		$self->{result} = "signed";
	}
}

=head1 METHODS

=head2 PRINT() - feed part of the message to the signer

  $dkim->PRINT("a line of the message\015\012");

Feeds content of the message being signed into the signer.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE() - call this when finished feeding in the message

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and generates a signature.

=head2 add_signature() - used by signer policy to create a new signature

  $dkim->add_signature(new Mail::DKIM::Signature(...));

Signer policies can use this method to specify complete parameters for
the signature to add, including what type of signature. For more information,
see Mail::DKIM::SignerPolicy.

=cut

sub add_signature
{
	my $self = shift;
	my $signature = shift;

	# create a canonicalization filter and algorithm
	my $algorithm_class = $signature->get_algorithm_class(
			$self->{"Algorithm"});
	my $algorithm = $algorithm_class->new(
			Signature => $signature,
			Debug_Canonicalization => $self->{Debug_Canonicalization},
		);
	push @{$self->{algorithms}}, $algorithm;
	return;
}

=head2 algorithm() - get or set the selected algorithm

  $alg = $dkim->algorithm;

  $dkim->algorithm("rsa-sha1");

=cut

sub algorithm
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Algorithm} = shift;
	}
	return $self->{Algorithm};
}

=head2 domain() - get or set the selected domain

  $alg = $dkim->domain;

  $dkim->domain("example.org");

=cut

sub domain
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Domain} = shift;
	}
	return $self->{Domain};
}

=head2 load() - load the entire message from a file handle

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the signer.  The message must use <CRLF> line
terminators (same as the SMTP protocol).

=cut

=head2 headers() - determine which headers to put in signature

  my $headers = $dkim->headers;

This is a string containing the names of the header fields that
will be signed, separated by colons.

=cut

# these are headers that "should" be included in the signature,
# according to the DKIM spec.
my @DEFAULT_HEADERS = qw(From Sender Reply-To Subject Date
	Message-ID To Cc MIME-Version
	Content-Type Content-Transfer-Encoding Content-ID Content-Description
	Resent-Date Resent-From Resent-Sender Resent-To Resent-cc
	Resent-Message-ID
	In-Reply-To References
	List-Id List-Help List-Unsubscribe List-Subscribe
	List-Post List-Owner List-Archive);

sub headers
{
	my $self = shift;
	croak "unexpected argument" if @_;

	# these are the header fields we found in the message we're signing
	my @found_headers = @{$self->{header_field_names}};

	# these are the headers we actually want to sign
	my @wanted_headers = @DEFAULT_HEADERS;
	if ($self->{Headers})
	{
		push @wanted_headers, split /:/, $self->{Headers};
	}

	my @headers =
		grep { my $a = $_;
			scalar grep { lc($a) eq lc($_) } @wanted_headers }
		@found_headers;
	return join(":", @headers);
}

# return nonzero if this is header we should sign
sub want_header
{
	my $self = shift;
	my ($header_name) = @_;

	#TODO- provide a way for user to specify which headers to sign
	return scalar grep { lc($_) eq lc($header_name) } @DEFAULT_HEADERS;
}

=head2 method() - get or set the selected canonicalization method

  $alg = $dkim->method;

  $dkim->method("relaxed");

=cut

sub method
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Method} = shift;
	}
	return $self->{Method};
}

=head2 message_originator() - access the "From" header

  my $address = $dkim->message_originator;

Returns the "originator address" found in the message. This is typically
the (first) name and email address found in the From: header. The returned
object is of type Mail::Address. To get just the email address part, do:

  my $email = $dkim->message_originator->address;


=head2 message_sender() - access the "From" or "Sender" header

  my $address = $dkim->message_sender;

Returns the "sender" found in the message. This is typically the (first)
name and email address found in the Sender: header. If there is no Sender:
header, it is the first name and email address in the From: header.
The returned object is of type Mail::Address, so to get just the email
address part, do:

  my $email = $dkim->message_sender->address;

The "sender" is the mailbox of the agent responsible for the actual
transmission of the message. For example, if a secretary were to send a
message for another person, the "sender" would be the secretary and
the "originator" would be the actual author.


=cut

=head2 selector() - get or set the current key selector

  $alg = $dkim->selector;

  $dkim->selector("alpha");

=cut

sub selector
{
	my $self = shift;
	if (@_ == 1)
	{
		$self->{Selector} = shift;
	}
	return $self->{Selector};
}

=head2 signature() - access the generated signature object

  my $signature = $dkim->signature;

Returns the generated signature. The signature is an object of type
Mail::DKIM::Signature. If multiple signatures were generated, this method
returns the last one.

The signature should be B<prepended> to the message to make the
resulting message. At the very least, it should precede any headers
that were signed.

=head2 signatures() - access list of generated signature objects

  my @signatures = $dkim->signatures;

Returns all generated signatures, as a list.

=cut

sub signatures
{
	my $self = shift;
	croak "no arguments allowed" if @_;
	return map { $_->signature } @{$self->{algorithms}};
}

=head1 SIGNER POLICIES

The new() constructor takes an optional Policy argument. This
can be a Perl object or class with an apply() method, or just a simple
subroutine reference. The method/subroutine will be called with the
signer object as an argument. The policy is responsible for checking the
message and specifying signature parameters. The policy must return a
nonzero value to create the signature, otherwise no signature will be
created. E.g.,

  my $policyfn = sub {
      my $dkim = shift;

      # specify signature parameters
      $dkim->algorithm("rsa-sha1");
      $dkim->method("relaxed");
      $dkim->domain("example.org");
      $dkim->selector("mx1");

      # return true value to create the signature
      return 1;
  };

Or the policy object can actually create the signature, using the
add_signature method within the policy object.
If you add a signature, you do not need to return a nonzero value.
This mechanism can be utilized to create multiple signatures.

  my $policyfn = sub {
      my $dkim = shift;
      $dkim->add_signature(
              new Mail::DKIM::Signature(
                      Algorithm => "rsa-sha1",
                      Method => "relaxed",
                      Headers => $dkim->headers,
                      Domain => "example.org",
                      Selector => "mx1",
              ));
      return;
  };

If no policy is specified, the default policy is used. The default policy
signs every message using the domain, algorithm, method, and selector
specified in the new() constructor.

=head1 SEE ALSO

Mail::DKIM::SignerPolicy

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
