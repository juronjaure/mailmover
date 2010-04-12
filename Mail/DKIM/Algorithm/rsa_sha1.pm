#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

use Mail::DKIM::PrivateKey;

package Mail::DKIM::Algorithm::rsa_sha1;
use base "Mail::DKIM::Algorithm::Base";
use Carp;
use MIME::Base64;
use Digest::SHA1;

sub init_digests
{
	my $self = shift;

	# initialize a SHA-1 Digest
	$self->{header_digest} = new Digest::SHA1;
	if ($self->{draft_version} eq "01")
	{
		$self->{body_digest} = new Digest::SHA1;
	}
	else
	{
		$self->{body_digest} = $self->{header_digest};
	}
}

sub sign
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 1);
	my ($private_key) = @_;

	my $digest = $self->{header_digest}->digest;
	my $signature = $private_key->sign_sha1_digest($digest);

	return encode_base64($signature, "");
}

sub verify
{
	my $self = shift;
	croak "wrong number of arguments" unless (@_ == 0);

	my $base64 = $self->signature->data;
	my $public_key = $self->signature->get_public_key;

	my $sig = decode_base64($base64);
	my $digest = $self->{header_digest}->digest;
	return unless $public_key->verify_sha1_digest($digest, $sig);
	return $self->check_body_hash;
}

1;

__END__

=head1 NAME

Mail::DKIM::Algorithm::rsa_sha1 - implements the rsa-sha1 signing algorithm for DKIM

=head1 CONSTRUCTOR

=head2 new() - create an object for the DKIM signing algorithm "rsa-sha1"

  my $algorithm = new Mail::DKIM::Algorithm::rsa_sha1(
                      Signature => $dkim_signature
                  );

=head1 METHODS

See Mail::DKIM::Algorithm::Base for the full list of methods supported
by this algorithm class.

=cut

