#
# Mail::SPF::Result
# SPF result class.
#
# (C) 2005-2007 Julian Mehnle <julian@mehnle.net>
# $Id: Result.pm 42 2007-01-20 01:17:05Z Julian Mehnle $
#
##############################################################################

package Mail::SPF::Result;

=head1 NAME

Mail::SPF::Result - SPF result class

=cut

use warnings;
use strict;

use utf8;  # Hack to keep Perl 5.6 from whining about /[\p{}]/.

use base 'Error', 'Mail::SPF::Base';
    # An SPF result is not really a code exception in ideology, but in form.
    # The Error base class fits our purpose, anyway.

use Mail::SPF::Util;

use Error ':try';

use constant TRUE   => (0 == 0);
use constant FALSE  => not TRUE;

use constant result_classes_by_code => {
    pass        => 'Mail::SPF::Result::Pass',
    fail        => 'Mail::SPF::Result::Fail',
    softfail    => 'Mail::SPF::Result::SoftFail',
    neutral     => 'Mail::SPF::Result::Neutral',
    none        => 'Mail::SPF::Result::None',
    error       => 'Mail::SPF::Result::Error',
    permerror   => 'Mail::SPF::Result::PermError',
    temperror   => 'Mail::SPF::Result::TempError'
};

use constant received_spf_header_identity_key_names_by_scope => {
    helo        => 'helo',
    mfrom       => 'envelope-from',
    pra         => 'pra'
};

use constant atext_pattern              => qr/[\p{IsAlnum}!#\$%&'*+\-\/=?^_`{|}~]/;

use constant dot_atom_pattern           => qr/
    (${\atext_pattern})+ ( \. (${\atext_pattern})+ )*
/x;

# Interface:
##############################################################################

=head1 SYNOPSIS

For the general usage of I<Mail::SPF::Result> objects in code that calls
Mail::SPF, see L<Mail::SPF>.  For the detailed interface of I<Mail::SPF::Result>
and its derivatives, see below.

=head2 Throwing results

    package Mail::SPF::Foo;
    use Error ':try';
    use Mail::SPF::Result;
    
    sub foo {
        if (...) {
            throw Mail::SPF::Result::Pass($server, $request);
        }
        else {
            throw Mail::SPF::Result::PermError($server, $request, 'Invalid foo');
        }
    }

=head2 Catching results

    package Mail::SPF::Bar;
    use Error ':try';
    use Mail::SPF::Foo;
    
    try {
        Mail::SPF::Foo->foo();
    }
    catch Mail::SPF::Result with {
        my ($result) = @_;
        ...
    };

=head2 Using results

    my $result_code     = $result->code;
    my $request         = $result->request;
    my $local_exp       = $result->local_explanation;
    my $authority_exp   = $result->authority_explanation
        if $result->can('authority_explanation');
    my $spf_header      = $result->received_spf_header;

=cut

# Implementation:
##############################################################################

=head1 DESCRIPTION

An object of class B<Mail::SPF::Result> represents the result of an SPF
request.

There is usually no need to construct an SPF result object directly using the
C<new> constructor.  Instead, use the C<throw> class method to signal to the
calling code that a definite SPF result has been determined.  In other words,
use Mail::SPF::Result and its derivatives just like exceptions.  See L<Error>
or L<perlfunc/eval> for how to handle exceptions in Perl.

=head2 Constructor

The following constructor is provided:

=over

=item B<new($server, $request)>: returns I<Mail::SPF::Result>

=item B<new($server, $request, $text)>: returns I<Mail::SPF::Result>

Creates a new SPF result object and associates the given I<Mail::SPF::Server>
and I<Mail::SPF::Request> objects with it.  An optional result text may be
specified.

=cut

sub new {
    my ($self, @args) = @_;
    
    local $Error::Depth = $Error::Depth + 1;
    
    $self =
        ref($self) ?                        # Was new() involed on a class or an object?
            bless({ %$self }, ref($self))   # Object: clone source result object.
        :   $self->SUPER::new();            # Class:  create new result object.
    
    # Set/override fields:
    $self->{server}  = shift(@args) if @args;
    defined($self->{server})
        or throw Mail::SPF::EOptionRequired('Mail::SPF server object required');
    $self->{request} = shift(@args) if @args;
    defined($self->{request})
        or throw Mail::SPF::EOptionRequired('Request object required');
    $self->{'-text'} = shift(@args) if @args;
    
    return $self;
}

=back

=head2 Class methods

The following class methods are provided:

=over

=item B<throw($server, $request)>: throws I<Mail::SPF::Result>

=item B<throw($server, $request, $text)>: throws I<Mail::SPF::Result>

Throws a new SPF result object, associating the given I<Mail::SPF::Server> and
I<Mail::SPF::Request> objects with it.  An optional result text may be
specified.

=cut

sub throw {
    my ($self, @args) = @_;
    local $Error::Depth = $Error::Depth + 1;
    $self = $self->new(@args);
        # Always create/clone a new result object, not just when throwing for the first time!
    die($Error::THROWN = $self);
}

=item B<name>: returns I<string>

Returns the trailing part of the name of the I<Mail::SPF::Result::*> class on
which it is invoked.  For example, returns C<NeutralByDefault> if invoked on
I<Mail::SPF::Result::NeutralByDefault>.  This method may also be used as an
instance method.

=cut

sub name {
    my ($self) = @_;
    my $class = ref($self) || $self;
    return $class =~ /^Mail::SPF::Result::(\w+)$/ ? $1 : $class;
}

=item B<code>: returns I<string>

Returns the result code (C<"pass">, C<"fail">, C<"softfail">, C<"neutral">,
C<"none">, C<"error">, C<"permerror">, C<"permerror">) of the
I<Mail::SPF::Result::*> class on which it is invoked.  This method may also be
used as an instance method.

=item B<class_by_code($code)>: returns I<class>

Maps the given result code to the corresponding I<Mail::SPF::Result::*> class.
If an unknown result code was specified, returns B<undef>.

=cut

sub class_by_code {
    my ($self, $code) = @_;
    return $self->result_classes_by_code->{lc($code)};
}

=item B<is_code($code)>: returns I<boolean>

If the class (or object) on which this method is invoked represents the given
result code (or a derivative code), returns B<true>.  Returns B<false>
otherwise.  This method may also be used as an instance method.

For example, C<< Mail::SPF::Result::Pass->is_code('pass') >> returns B<true>.

=cut

sub is_code {
    my ($self, $code) = @_;
    my $suspect_class = $self->class_by_code($code);
    return FALSE if not defined($suspect_class);
    return $self->isa($suspect_class);
}

=back

=head2 Instance methods

The following instance methods are provided:

=over

=item B<throw>: throws I<Mail::SPF::Result>

=item B<throw($server, $request)>: throws I<Mail::SPF::Result>

=item B<throw($server, $request, $text)>: throws I<Mail::SPF::Result>

Re-throws an existing SPF result object.  If I<Mail::SPF::Server> and
I<Mail::SPF::Request> objects are specified, associates them with the result
object, replacing the prior server and request objects.  If a result text is
specified as well, overrides the prior result text.

=item B<code>: returns I<string>

Returns the result code of the result object.

=item B<server>: returns I<Mail::SPF::Server>

Returns the Mail::SPF server object that produced the result at hand.

=item B<request>: returns I<Mail::SPF::Request>

Returns the SPF request that led to the result at hand.

=cut

# Read-only accessors:
__PACKAGE__->make_accessor($_, TRUE)
    foreach qw(server request);

=item B<text>: returns I<string>

Returns the text message of the result object.

=item B<stringify>: returns I<string>

Returns the result's name and text message formatted as a string.  You can
simply use a Mail::SPF::Result object as a string for the same effect, see
L</OVERLOADING>.

=cut

sub stringify {
    my ($self) = @_;
    return sprintf("%s (%s)", $self->name, $self->SUPER::stringify);
}

=item B<local_explanation>: returns I<string>; throws I<Mail::SPF::EDNSError>,
I<Mail::SPF::EInvalidMacroString>

Returns a locally generated explanation for the result.

The local explanation is prefixed with the authority domain whose sender policy
is responsible for the result.  If the responsible sender policy referred to
another domain's policy (using the C<include> mechanism or the C<redirect>
modifier), that other domain which is I<directly> responsible for the result is
also included in the local explanation's head.  For example:

    example.com: <local-explanation>

The authority domain C<example.com>'s sender policy is directly responsible for
the result.

    example.com ... other.example.org: <local-explanation>

The authority domain C<example.com> (directly or indirectly) referred to the
domain C<other.example.org>, whose sender policy then led to the result.

=cut

sub local_explanation {
    my ($self) = @_;
    my $local_explanation = $self->{local_explanation};
    
    return $local_explanation
        if defined($local_explanation);
    
    # Prepare local explanation:
    my $request = $self->{request};
    $local_explanation = $request->state('local_explanation');
    if (defined($local_explanation)) {
        $local_explanation = sprintf("%s (%s)", $local_explanation->expand, lcfirst($self->text));
    }
    else {
        $local_explanation = $self->text;
    }
    
    # Resolve authority domains of root-request and bottom sub-request:
    my $root_request = $request->root_request;
    $local_explanation =
        $request == $root_request ?
            sprintf("%s: %s", $request->authority_domain, $local_explanation)
        :   sprintf("%s ... %s: %s",
                $root_request->authority_domain, $request->authority_domain, $local_explanation);
    
    return $self->{local_explanation} = $local_explanation;
}

=item B<received_spf_header>: returns I<string>

Returns a string containing an appropriate C<Received-SPF> header field for the
result object.  The header field is not line-wrapped and contains no trailing
newline character.

=cut

sub received_spf_header {
    my ($self) = @_;
    return $self->{received_spf_header}
        if defined($self->{received_spf_header});
    my $identity_key_name =
        $self->received_spf_header_identity_key_names_by_scope->{$self->{request}->scope};
    my @info_pairs = (
        receiver            => $self->{server}->hostname || 'unknown',
        identity            => $self->{request}->scope,
        $identity_key_name  => $self->{request}->identity,
        (
            ($self->{request}->scope ne 'helo' and defined($self->{request}->helo_identity)) ?
                (helo       => $self->{request}->helo_identity)
            :   ()
        ),
        'client-ip'         => Mail::SPF::Util->ip_address_to_string($self->{request}->ip_address)
    );
    my $info_string;
    while (@info_pairs) {
        my $key   = shift(@info_pairs);
        my $value = shift(@info_pairs);
        $info_string .= '; ' if defined($info_string);
        if ($value !~ /^${\dot_atom_pattern}$/o) {
            $value =~ s/(["\\])/\\$1/g;   # Escape '\' and '"' characters.
            $value = '"' . $value . '"';  # Double-quote value.
        }
        $info_string .= "$key=$value";
    }
    return $self->{received_spf_header} = sprintf(
        "Received-SPF: %s (%s) %s",
        $self->code,
        $self->local_explanation,
        $info_string
    );
}

=back

=head1 OVERLOADING

If a Mail::SPF::Result object is used as a I<string>, the L</stringify> method
is used to convert the object into a string.

=head1 RESULT CLASSES

The following result classes are provided:

=over

=item I<Mail::SPF::Result::Pass>

=item I<Mail::SPF::Result::Fail>

The following additional instance method is provided:

=over

=item B<authority_explanation>: returns I<string>; throws I<Mail::SPF::EDNSError>,
I<Mail::SPF::EInvalidMacroString>

Returns the authority domain's explanation for the result.  Be aware that the
authority domain may be a malicious party and thus the authority explanation
should not be trusted blindly.  See RFC 4408, 10.5, for a detailed discussion
of this issue.

=back

=item I<Mail::SPF::Result::SoftFail>

=item I<Mail::SPF::Result::Neutral>

=item I<Mail::SPF::Result::NeutralByDefault>

This is a special-case of the C<neutral> result that is thrown as a default
when "falling off" the end of the record during evaluation.  See RFC 4408,
4.7.

=item I<Mail::SPF::Result::None>

=item I<Mail::SPF::Result::Error>

The following sub-classes of I<Mail::SPF::Result::Error> are provided:

=over

=item I<Mail::SPF::Result::PermError>

=item I<Mail::SPF::Result::TempError>

=back

=cut

package Mail::SPF::Result::Pass;
our @ISA = 'Mail::SPF::Result';
use constant code => 'pass';

package Mail::SPF::Result::Fail;
our @ISA = 'Mail::SPF::Result';
use Error ':try';
use Mail::SPF::Exception;
use constant code => 'fail';

sub authority_explanation {
    my ($self) = @_;
    my $authority_explanation = $self->{authority_explanation};
    
    return $authority_explanation
        if defined($authority_explanation);
    
    my $server  = $self->{server};
    my $request = $self->{request};
    
    my $authority_explanation_macrostring = $request->state('authority_explanation');
    
    # If an explicit explanation was specified by the authority domain...
    if (defined($authority_explanation_macrostring)) {
        try {
            # ... then try to expand it:
            $authority_explanation = $authority_explanation_macrostring->expand;
        }
        catch Mail::SPF::EInvalidMacroString with {};
            # Ignore expansion errors and leave authority explanation undefined.
    }
    
    # If no authority explanation could be determined so far...
    if (not defined($authority_explanation)) {
        # ... then use the server's default authority explanation:
        $authority_explanation =
            $server->default_authority_explanation->new(request => $request)->expand;
    }
    
    return $self->{authority_explanation} = $authority_explanation;
}

package Mail::SPF::Result::SoftFail;
our @ISA = 'Mail::SPF::Result';
use constant code => 'softfail';

package Mail::SPF::Result::Neutral;
our @ISA = 'Mail::SPF::Result';
use constant code => 'neutral';

package Mail::SPF::Result::NeutralByDefault;
our @ISA = 'Mail::SPF::Result::Neutral';
    # This is a special-case of the Neutral result that is thrown as a default
    # when "falling off" the end of the record.  See Mail::SPF::Record::eval().

package Mail::SPF::Result::None;
our @ISA = 'Mail::SPF::Result';
use constant code => 'none';

package Mail::SPF::Result::Error;
our @ISA = 'Mail::SPF::Result';
use constant code => 'error';

package Mail::SPF::Result::PermError;
our @ISA = 'Mail::SPF::Result::Error';
use constant code => 'permerror';

package Mail::SPF::Result::TempError;
our @ISA = 'Mail::SPF::Result::Error';
use constant code => 'temperror';

=back

=head1 SEE ALSO

L<Mail::SPF>, L<Mail::SPF::Server>, L<Error>, L<perlfunc/eval>

L<http://www.ietf.org/rfc/rfc4408.txt>

For availability, support, and license information, see the README file
included with Mail::SPF.

=head1 AUTHORS

Julian Mehnle <julian@mehnle.net>

=cut

package Mail::SPF::Result;

TRUE;
