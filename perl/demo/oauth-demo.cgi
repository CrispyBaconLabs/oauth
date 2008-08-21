#!/usr/bin/env perl

use strict;
use lib qw(/home/kg23/local/share/perl/5.8.4 /home/kg23/local/lib/perl/5.8.4);
use CGI::Carp qw(fatalsToBrowser);
use OAuthDemo;
$ENV{OAUTH_DEMO_HOME} = '.' unless defined $ENV{OAUTH_DEMO_HOME};
my $app = OAuthDemo->new();
$app->mode_param( path_info => 1 );
$app->run();
