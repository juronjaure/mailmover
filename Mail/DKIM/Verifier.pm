#!/usr/bin/perl

# Copyright 2005-2007 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::Signature;
use Mail::DKIM::DkSignature;
use Mail::Address;

=head1 NAME

Mail::DKIM::Verifier - verifies a DKIM-signed message

=head1 SYNOPSIS

  use Mail::DKIM::Verifier;

  # create a verifier object
  my $dkim = Mail::DKIM::Verifier->new();

  # read an email from a file handle
  $dkim->load(*STDIN);

  # or read an email and pass it into the verifier, incrementally
  while (<STDIN>)
  {
      # remove local line terminators
      chomp;
      s/\015$//;

      # use SMTP line terminators
      $dkim->PRINT("$_\015\012");
  }
  $dkim->CLOSE;

  # what is the result of the verify?
  my $result = $dkim->result;

=cut

=head1 DESCRIPTION

The verifier object allows an email message to be scanned for DKIM and
DomainKeys signatures and those signatures to be verified. The verifier
tracks the state of the message as it is read into memory. When the
message has been completely read, the signatures are verified and the
results of the verification can be accessed.

To use the verifier, first create the verifier object. Then start
"feeding" it the email message to be verified. When all the headers
have been read, the verifier:

 1. checks whether any DomainKeys/DKIM signatures were found
 2. queries for the public keys needed to verify the signatures
 3. sets up the appropriate algorithms and canonicalization objects
 4. canonicalizes the headers and computes the header hash

Then, when the body of the message has been completely fed into the
verifier, the body hash is computed and the signatures are verified.

=head1 CONSTRUCTOR

=head2 new() - construct an object-oriented verifier

  my $dkim = Mail::DKIM::Verifier->new();

  my $dkim = Mail::DKIM::Verifier->new(%options);

The only option supported at this time is:

=over

=item Debug_Canonicalization

if specified, the canonicalized message for the first signature
is written to the referenced string or file handle.

=back

=cut

package Mail::DKIM::Verifier;
use base "Mail::DKIM::Common";
use Carp;
use Error ":try";
our $VERSION = '0.28';

sub init
{
	my $self = shift;
	$self->SUPER::init;
	$self->{signatures} = [];
}

# @{$dkim->{signatures}}
#   array of L<Mail::DKIM::Signature> objects, representing all
#   syntactically valid signatures found in the header,
#   ordered from the top of the header to the bottom.
#
# $dkim->{signature_reject_reason}
#   simple string listing a reason, if any, for not using a signature.
#   This may be a helpful diagnostic if there is a signature in the header,
#   but was found not to be valid. It will be ambiguous if there are more
#   than one signatures that could not be used.
#
# $dkim->{signature}
#   the L<Mail::DKIM::Signature> selected as the "best" signature.
#
# @{$dkim->{headers}}
#   array of strings, each member is one header, in its original format.
#
# $dkim->{algorithms}
#   array of algorithms, one for each signature being verified.
#
# $dkim->{result}
#   string; the result of the verification (see the result() method)
#

sub handle_header
{
	my $self = shift;
	my ($field_name, $contents, $line) = @_;

	$self->SUPER::handle_header($field_name, $contents);

	if (lc($field_name) eq "dkim-signature")
	{
		$self->add_signature($line);
	}

	if (lc($field_name) eq "domainkey-signature")
	{
		$self->add_signature_dk($line);
	}
}

sub add_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($contents) = @_;

	eval
	{
		my $signature = Mail::DKIM::Signature->parse($contents);
		push @{$self->{signatures}}, $signature;
	};
	if ($@)
	{
		chomp (my $E = $@);
		$self->{signature_reject_reason} = $E;
	}
}

# parses a DomainKeys-type signature
sub add_signature_dk
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($contents) = @_;

	eval
	{
		my $signature = Mail::DKIM::DkSignature->parse($contents);
		push @{$self->{signatures}}, $signature;
	};
	if ($@)
	{
		chomp (my $E = $@);
		$self->{signature_reject_reason} = $E;
	}
}

sub check_signature
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($signature) = @_;

	unless ($signature->algorithm
		&& $signature->get_algorithm_class($signature->algorithm))
	{
		# unsupported algorithm
		$self->{signature_reject_reason} = "unsupported algorithm";
		if (defined $signature->algorithm)
		{
			$self->{signature_reject_reason} .= " " . $signature->algorithm;
		}
		return 0;
	}

	unless ($signature->check_canonicalization)
	{
		# unsupported canonicalization method
		$self->{signature_reject_reason} = "unsupported canonicalization";
		if (defined $signature->method)
		{
			$self->{signature_reject_reason} .= " " . $signature->method;
		}
		return 0;
	}

	unless ($signature->check_protocol)
	{
		# unsupported query protocol
		$self->{signature_reject_reason} =
			!defined($signature->protocol) ? "missing q tag"
			: "unsupported query protocol, q=" . $signature->protocol;
		return 0;
	}

	unless ($signature->domain ne '')
	{
		# no domain specified
		$self->{signature_reject_reason} =
			!defined($signature->domain) ? "missing d tag"
			: "invalid domain in d tag";
		return 0;
	}

	unless ($signature->selector)
	{
		# no selector specified
		$self->{signature_reject_reason} = "missing s tag";
		return 0;
	}

	# check domain against message From: and Sender: headers
#	my $responsible_address = $self->message_originator;
#	if (!$responsible_address)
#	{
#		# oops, no From: or Sender: header
#		die "No From: or Sender: header";
#	}
#
#	my $senderdomain = $responsible_address->host;
#	my $sigdomain = $signature->domain;
#	if (!$self->match_subdomain($senderdomain, $sigdomain))
#	{
#		$self->{signature_reject_reason} = "unmatched domain";
#		return 0;
#	}

	return 1;
}

sub check_public_key
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($signature, $public_key) = @_;

	my $result = 0;
	eval
	{
		# check public key's allowed hash algorithms
		$result = $public_key->check_hash_algorithm(
				$signature->hash_algorithm);

		# TODO - check public key's granularity
	};
	if ($@)
	{
		my $E = $@;
		chomp $E;
		$self->{signature_reject_reason} = $E;
	}
	return $result;
}

sub match_subdomain
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 2);
	my ($subdomain, $superdomain) = @_;

	my $tmp = substr(".$subdomain", -1 - length($superdomain));
	return (".$superdomain" eq $tmp);
}

#
# called when the verifier has received the last of the message headers
# (body is still to come)
#
sub finish_header
{
	my $self = shift;

	# Signatures we found and were successfully parsed are stored in
	# $self->{signatures}. If none were found, our result is "none".

	if (@{$self->{signatures}} == 0
		&& !defined($self->{signature_reject_reason}))
	{
		$self->{result} = "none";
		return;
	}

	# For each parsed signature, check it for validity. If none are valid,
	# our result is "invalid" and our result detail will be the reason
	# why the last signature was invalid.

	my @valid = ();
	foreach my $signature (@{$self->{signatures}})
	{
		next unless ($self->check_signature($signature));

		# get public key
		my $pkey;
		eval
		{
			$pkey = $signature->get_public_key;
		};
		if ($@)
		{
			my $E = $@;
			chomp $E;
			$self->{signature_reject_reason} = $E;
		}

		if ($pkey)
		{
			$self->check_public_key($signature, $pkey)
				or next;
		}
		else
		{
			# public key not available
			next;
		}

		# this signature is ok
		push @valid, $signature;
	}

	unless (@valid)
	{
		# no valid signatures found
		$self->{result} = "invalid";
		$self->{details} = $self->{signature_reject_reason};
		return;
	}

	# now, for each valid signature, create an "algorithm" object which
	# will process the message

	$self->{algorithms} = [];
	foreach my $signature (@valid)
	{
		# create a canonicalization filter and algorithm
		my $algorithm_class = $signature->get_algorithm_class(
					$signature->algorithm);
		my $algorithm = $algorithm_class->new(
					Signature => $signature,
					Debug_Canonicalization => $self->{Debug_Canonicalization},
				);

		# output header as received so far into canonicalization
		foreach my $line (@{$self->{headers}})
		{
			$algorithm->add_header($line);
		}
		$algorithm->finish_header;

		# save the algorithm
		push @{$self->{algorithms}}, $algorithm;
	}
}

sub finish_body
{
	my $self = shift;

	foreach my $algorithm (@{$self->{algorithms}})
	{
		# finish canonicalizing
		$algorithm->finish_body;

		# verify signature
		my $result;
		my $details;
		local $@ = undef;
		eval
		{
			$result = $algorithm->verify() ? "pass" : "fail";
			$details = $algorithm->{verification_details} || $@;
		};
		if ($@)
		{
			# see also add_signature
			chomp (my $E = $@);
			if ($E =~ /(OpenSSL error: .*?) at /)
			{
				$E = $1;
			}
			elsif ($E =~ /^(panic:.*?) at /)
			{
				$E = "OpenSSL $1";
			}
			$result = "fail";
			$details = $E;
		}

		# save the results of this signature verification
		$algorithm->{result} = $result;
		$algorithm->{details} = $details;
		$algorithm->signature->result($result, $details);

		# collate results ... ignore failed signatures if we already got
		# one to pass
		if (!$self->{result} || $result eq "pass")
		{
			$self->{signature} = $algorithm->signature;
			$self->{result} = $result;
			$self->{details} = $details;
		}
	}
}

=head1 METHODS

=head2 PRINT() - feed part of the message to the verifier

  $dkim->PRINT("a line of the message\015\012");
  $dkim->PRINT("more of");
  $dkim->PRINT(" the message\015\012bye\015\012");

Feeds content of the message being verified into the verifier.
The API is designed this way so that the entire message does NOT need
to be read into memory at once.

=head2 CLOSE() - call this when finished feeding in the message

  $dkim->CLOSE;

This method finishes the canonicalization process, computes a hash,
and verifies the signature.

=head2 fetch_author_policy() - retrieves a signing policy from DNS

  my $policy = $dkim->fetch_author_policy;
  my $policy_result = $policy->apply($dkim);

The "author" policy, as I call it, is the DKIM Sender Signing Practices
record as described in Internet Draft draft-ietf-dkim-ssp-00-01dc.
I call it the "author" policy because it is keyed to the email address
in the From: header, i.e. the author of the message.

The IETF is still actively working on this Internet Draft, so the
exact mechanisms are subject to change.

If the email being verified has no From header at all
(which violates email standards),
then this method will C<die>.

The result of the apply() method is one of: "accept", "reject", "neutral".

=cut

sub fetch_author_policy
{
	my $self = shift;
	use Mail::DKIM::DkimPolicy;

	# determine address found in the "From"
	my $author = $self->message_originator;
	$author &&= $author->address;

	# fetch the policy
	return Mail::DKIM::DkimPolicy->fetch(
			Protocol => "dns",
			Author => $author,
			);
}

=head2 fetch_sender_policy() - retrieves a signing policy from DNS

  my $policy = $dkim->fetch_sender_policy;
  my $policy_result = $policy->apply($dkim);

The "sender" policy is the sender signing policy as described by the
DomainKeys specification, now available in RFC4870(historical).
I call it the "sender" policy because it is keyed to the email address
in the Sender: header, or the From: header if there is no Sender header.
This is the person whom the message claims as the "transmitter" of the
message (not necessarily the author).

If the email being verified has no From or Sender header from which to
get an email address (which violates email standards),
then this method will C<die>.

The result of the apply() method is one of: "accept", "reject", "neutral".

=cut

sub fetch_sender_policy
{
	my $self = shift;
	use Mail::DKIM::Policy;

	# determine addresses found in the "From" and "Sender" headers
	my $author = $self->message_originator;
	$author &&= $author->address;
	my $sender = $self->message_sender;
	$sender &&= $sender->address;

	# fetch the policy
	return Mail::DKIM::Policy->fetch(
			Protocol => "dns",
			Author => $author,
			Sender => $sender,
			);
}

=head2 load() - load the entire message from a file handle

  $dkim->load($file_handle);

Reads a complete message from the designated file handle,
feeding it into the verifier. The message must use <CRLF> line
terminators (same as the SMTP protocol).

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


=head2 result() - access the result of the verification

  my $result = $dkim->result;

Gives the result of the verification. The following values are possible:

=over

=item pass

Returned if a valid DKIM-Signature header was found, and the signature
contains a correct value for the message.

=item fail

Returned if a valid DKIM-Signature header was found, but the signature
does not contain a correct value for the message.

=item invalid

Returned if no valid DKIM-Signature headers were found, but there is at
least one invalid DKIM-Signature header. For a reason why a
DKIM-Signature header found in the message was invalid,
see $dkim->{signature_reject_reason}.

=item none

Returned if no DKIM-Signature headers (valid or invalid) were found.

=back

In case of multiple signatures, the "best" result will be returned.
Best is defined as "pass", followed by "fail", "invalid", and "none".

=cut

=head2 result_detail() - access the result, plus details if available

  my $detail = $dkim->result_detail;

The detail is constructed by taking the result (i.e. one of "pass", "fail",
"invalid" or "none") and appending any details provided by the verification
process in parenthesis.

The following are possible results from the result_detail() method:

  pass
  fail (bad RSA signature)
  fail (headers have been altered)
  fail (body has been altered)
  invalid (unsupported canonicalization)
  invalid (unsupported query protocol)
  invalid (invalid domain in d tag)
  invalid (missing q tag)
  invalid (missing d tag)
  invalid (missing s tag)
  invalid (unsupported v=0.1 tag)
  invalid (no public key available)
  invalid (public key: does not support email)
  invalid (public key: does not support hash algorithm 'sha1')
  invalid (public key: unsupported key type)
  invalid (public key: missing p= tag)
  invalid (public key: revoked)
  invalid (public key: invalid data)
  invalid (public key: OpenSSL error: ...)
  none

=head2 signature() - access the message's DKIM signature

  my $sig = $dkim->signature;

Accesses the signature found and verified in this message. The returned
object is of type Mail::DKIM::Signature.

In case of multiple signatures, the signature with the "best" result will
be returned.
Best is defined as "pass", followed by "fail", "invalid", and "none".

=cut

#EXPERIMENTAL
# =head2 signatures() - access all of this message's signatures
#
#   my @all_signatures = $dkim->signatures;
#
# =cut
#TODO
# how would the caller get the verification results of each signature?
# are they stored in the signature object?
sub signatures
{
	my $self = shift;
	croak "unexpected argument" if @_;

	return map { $_->signature } @{$self->{algorithms}};
}

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
