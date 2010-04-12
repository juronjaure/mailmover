#!/usr/bin/perl

# Copyright 2005-2006 Messiah College. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.
#
# Written by Jason Long <jlong@messiah.edu>

use strict;
use warnings;

package Mail::DKIM::SignerPolicy;

1;

__END__

=head1 NAME

Mail::DKIM::SignerPolicy - determines signing parameters for a message

=head1 DESCRIPTION

Objects of type Mail::DKIM::SignerPolicy are used by Mail::DKIM::Signer.
To take advantage of policy objects, create your own Perl class that
extends this class. The only method you need to provide is the apply()
method.

The apply() method takes as a parameter the Mail::DKIM::Signer object.
Using this object, it can determine some properties of the message (e.g.
what the From: address or Sender: address is). Then it sets various
signer properties as desired. The apply() method should
return a nonzero value if the message should be signed. If a false value
is returned, then the message is "skipped" (i.e. not signed).

Here is an example of a policy that always returns the same values:

  package MySignerPolicy;
  use base "Mail::DKIM::SignerPolicy";

  sub apply
  {
      my $self = shift;
      my $signer = shift;
  
      $signer->algorithm("rsa-sha1");
      $signer->method("relaxed");
      $signer->domain("example.org");
      $signer->selector("selector1");
  
      return 1;
  }

To use this policy, simply specify the name of the class as the Policy
parameter...

  my $dkim = Mail::DKIM::Signer->new_object(
                  Policy => "MySignerPolicy",
                  KeyFile => "private.key"
             );

=head1 ADVANCED

You can also have the policy actually build the signature for the Signer
to use. To do this, call the signer's add_signature() method from within
your apply() callback. E.g.,

  sub apply
  {
      my $self = shift;
      my $signer = shift;
  
      $signer->add_signature(
              new Mail::DKIM::Signature(
                  Algorithm => $signer->algorithm,
                  Method => $signer->method,
                  Headers => $signer->headers,
                  Domain => $signer->domain,
                  Selector => $signer->selector,
              ));
      return;
  }

Again, if you do not want any signatures, return zero or undef. If you
use add_signature() to create a signature, the default signature will
not be created, even if you return nonzero.

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
