package Net::OAuth::RenewAccessTokenResponse;
use warnings;
use strict;
use base 'Net::OAuth::Response';

__PACKAGE__->add_required_message_params(qw/token_secret/);
__PACKAGE__->add_optional_message_params(qw/session_handle/);
__PACKAGE__->add_optional_message_params(qw/expires_in/);
__PACKAGE__->add_optional_message_params(qw/authorization_expires_in/);
sub allow_extra_params {1}

=head1 NAME

Net::OAuth::AccessTokenResponse - An OAuth protocol response to renew an Access Token

=head1 SEE ALSO

L<Net::OAuth::Response>, L<http://oauth.net>

=head1 AUTHOR

Keith Grennan, C<< <kgrennan at cpan.org> >>

=head1 COPYRIGHT & LICENSE

Copyright 2007 Keith Grennan, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1;