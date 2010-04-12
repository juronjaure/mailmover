#!/usr/bin/perl

use strict;
use warnings;

package Mail::DKIM;
our $VERSION = '0.28';

1;
__END__

=head1 NAME

Mail::DKIM - Signs/verifies Internet mail with DKIM/DomainKey signatures

=head1 SYNOPSIS

  # verify a message
  use Mail::DKIM::Verifier;

  # create a verifier object
  my $dkim = Mail::DKIM::Verifier->new_object();

  # read an email from stdin, pass it into the verifier
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

=head1 DESCRIPTION

This Perl module is part of the dkimproxy program, located at
http://jason.long.name/dkimproxy/. I've tried to abstract out the DKIM
parts into this module, for use in other programs.

The Mail::DKIM module uses an object-oriented interface. You use one of
two different classes, depending on whether you are signing or verifying
a message. To sign, use the Mail::DKIM::Signer class. To verify, use the
Mail::DKIM::Verifier class. Simple, eh?

=head1 SEE ALSO

Mail::DKIM::Signer,
Mail::DKIM::Verifier

http://jason.long.name/dkimproxy/

=head1 KNOWN BUGS

The DKIM standard is still in development, so by the time you read this,
this module may already be broken with regards to the latest DKIM
specification.

The "sender signing policy" component is still under construction. The
sender signing policy is supposed to identify the practice of the message
author, so you could for example reject a message from an author who claims
they always sign their messages. See Mail::DKIM::Policy.

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
