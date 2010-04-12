#!/usr/bin/perl

# Copyright 2005-2007 Messiah College.
# Jason Long <jlong@messiah.edu>

# Copyright (c) 2004 Anthony D. Urso. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

use strict;
use warnings;

package Mail::DKIM::DkimPolicy;
use base "Mail::DKIM::Policy";
# base class is used for parse(), as_string()

use Mail::DKIM::DNS;

=head1 NAME

Mail::DKIM::DkimPolicy - implements DKIM Sender Signing Practices records

=head1 CONSTRUCTORS

=head2 fetch() - lookup a DKIM signing practices record

  my $policy = Mail::DKIM::DkimPolicy->fetch(
            Protocol => "dns",
            Author => 'jsmith@example.org',
          );

=cut

sub fetch
{
	my $class = shift;
	my %prms = @_;

	($prms{'Protocol'} eq "dns")
		or die "invalid protocol '$prms{Protocol}'\n";

	if ($prms{Author} && !$prms{Domain})
	{
		(undef, $prms{Domain}) = split(/\@/, $prms{Author}, 2);
	}

	unless ($prms{Domain})
	{
		die "no domain to fetch policy for\n";
	}

	# IETF seems poised to create policy records this way
	my $host = "_policy._domainkey." . $prms{Domain};

	#
	# perform DNS query for domain policy...
	#   if the query takes too long, we should catch it and generate
	#   an error
	#
	my $resp = Mail::DKIM::DNS::query($host, "TXT");
	unless ($resp)
	{
		# no response => NXDOMAIN, use default policy
		return $class->default;
	}

	my $strn;
	foreach my $ans ($resp->answer) {
		next unless $ans->type eq "TXT";
		$strn = join "", $ans->char_str_list;
	}

	unless ($strn)
	{
		# empty record found in DNS, use default policy
		return $class->default;
	}

	return $class->parse(
			String => $strn,
			Domain => $prms{Domain},
			);
}

=head2 new() - construct a default policy object

  my $policy = Mail::DKIM::DkimPolicy->new;

=cut

sub new
{
	my $class = shift;
	return $class->parse(String => "o=~");
}

#undocumented private class method
our $DEFAULT_POLICY;
sub default
{
	my $class = shift;
	$DEFAULT_POLICY ||= $class->new;
	return $DEFAULT_POLICY;
}

=head1 METHODS

=head2 apply() - apply the policy to the results of a DKIM verifier

  my $result = $policy->apply($dkim_verifier);

The caller must provide an instance of L<Mail::DKIM::Verifier>, one which
has already been fed the message being verified.

Possible results are:

=over

=item accept

The message is approved by the sender signing policy.

=item reject

The message is rejected by the sender signing policy.
It can be considered very suspicious.

=item neutral

The message is neither approved nor rejected by the sender signing
policy. It can be considered somewhat suspicious.

=back

=cut

sub apply
{
	my $self = shift;
	my ($dkim) = @_;

	# first_party indicates whether there is a DKIM signature with
	# an i= tag matching the address in the From: header
	my $first_party;

	#FIXME - if there are multiple verified signatures, each one
	# should be checked

	foreach my $signature ($dkim->signatures)
	{
		next if $signature->result ne "pass";

		my $oa = $dkim->message_originator->address;
		if ($signature->identity_matches($oa))
		{
			# found a first party signature
			$first_party = 1;
			last;
		}
	}

	#TODO - consider testing flag

	return "accept" if $first_party;
	return "reject" if ($self->signall_strict && !$self->testing);

	if ($self->signall)
	{
		# is there ANY valid signature?
		my $verify_result = $dkim->result;
		return "accept" if $verify_result eq "pass";
	}

	return "reject" if ($self->signall && !$self->testing);
	return "neutral";
}

=head2 flags() - get or set the flags (t=) tag

A colon-separated list of flags. Flag values are:

=over

=item y

The entity is testing signing practices, and the Verifier
SHOULD NOT consider a message suspicious based on the record.

=item s

The signing practices apply only to the named domain, and
not to subdomains.

=back

=cut

sub flags
{
	my $self = shift;

	(@_) and 
		$self->{tags}->{t} = shift;

	$self->{tags}->{t};
}

=head2 is_implied_default_policy() - is this policy implied?

  my $is_implied = $policy->is_implied_default_policy;

If you fetch the policy for a particular domain, but that domain
does not have a policy published, then the "default policy" is
in effect. Use this method to detect when that happens.

=cut

sub is_implied_default_policy
{
	my $self = shift;
	my $default_policy = ref($self)->default;
	return ($self == $default_policy);
}

=head2 location() - where the policy was fetched from

If the policy is domain-wide, this will be domain where the policy was
published.

If the policy is user-specific, TBD.

If nothing is published for the domain, and the default policy
was returned instead, the location will be C<undef>.

=cut

sub location
{
	my $self = shift;
	return $self->{Domain};
}

=head2 policy() - get or set the outbound signing policy (dkim=) tag

  my $sp = $policy->policy;

Outbound signing policy for the entity. Possible values are:

=over

=item C<unknown>

The default. The entity may sign some or all email.

=item C<all>

All mail from the entity is signed.
(The DKIM signature can use any domain, not necessarily matching
the From: address.)

=item C<strict>

All mail from the entity is signed with Originator signatures.
(The DKIM signature uses a domain matching the From: address.)

=back

=cut

sub policy
{
	my $self = shift;

	(@_) and
		$self->{tags}->{dkim} = shift;

	if (defined $self->{tags}->{dkim})
	{
		return $self->{tags}->{dkim};
	}
	elsif (defined $self->{tags}->{o})
	{
		return $self->{tags}->{o};
	}
	else
	{
		return "unknown";
	}
}

=head2 signall() - true if policy is "all"

=cut

sub signall
{
	my $self = shift;

	return $self->policy &&
		($self->policy =~ /all/i
		|| $self->policy eq "-"); # an older symbol for "all"
}

=head2 signall_strict() - true if policy is "strict"

=cut

sub signall_strict
{
	my $self = shift;

	return $self->policy &&
		($self->policy =~ /strict/i
		|| $self->policy eq "!");  # "!" is an older symbol for "strict"
}

sub signsome
{
	my $self = shift;

	$self->policy or
		return 1;

	$self->policy eq "~" and
		return 1;

	return;
}

=head2 testing() - checks the testing flag

  my $testing = $policy->testing;

If nonzero, the testing flag is set on the signing policy, and the
verify should not consider a message suspicious based on this policy.

=cut

sub testing
{
	my $self = shift;
	my $t = $self->flags;
	($t && $t =~ /y/i)
		and return 1;
	return;
}

1;

=head1 BUGS

=over

=item *

If a sender signing policy is not found for a given domain, the
fetch() method should search the parent domains, according to
section 4 of the dkim-ssp Internet Draft.

=back

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
