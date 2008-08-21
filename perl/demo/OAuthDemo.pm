package OAuthDemo;
use strict;
use base 'CGI::Application';
use CGI::Application::Plugin::AutoRunmode;
use CGI::Application::Plugin::TT;
use CGI::Application::Plugin::Session;
use CGI::Application::Plugin::Config::YAML;

use Net::OAuth;
use Crypt::OpenSSL::RSA;
use File::Slurp;
use Data::Random qw(rand_chars);
use LWP::UserAgent;
use HTTP::Request::Common;
use XML::LibXML;
use XML::LibXML::XPathContext;
use File::Spec;
use List::Util 'shuffle';

sub cgiapp_init {
        my $self = shift;
	$self->config_file(File::Spec->catfile($ENV{OAUTH_DEMO_HOME}, 'config.yml'));
	$self->tt_include_path($ENV{OAUTH_DEMO_HOME});
}

sub _get_key {
	my $self = shift;
	my $ketstring = read_file($self->config_param('private_key'));
	return Crypt::OpenSSL::RSA->new_private_key($ketstring);
}

sub _redirect {
	my $self = shift;
	my $url = shift || $self->config_param('base_url');
	$self->header_type('redirect');
        $self->header_props(-url=>$url);
	return "Redirecting to $url";
}

sub _default_request_params {
	my $self = shift;
	return (
		consumer_key => $self->config_param('consumer_key'),
		consumer_secret => '',
		request_method => 'GET',
		signature_method => 'RSA-SHA1',
		timestamp => time,
		nonce => join('', rand_chars(size=>16, set=>'alphanumeric')),
	);
}

sub default : StartRunmode {
	my $self = shift;
	my @contacts;
	if (defined $self->session->param('token')) {
		my $request = Net::OAuth->request("protected resource")->new(
		    $self->_default_request_params,
		    request_url => $self->config_param('contacts_feed_url'),
		    token => $self->session->param('token'),
		    token_secret => '',
		);

		#print "base_string:", $request->signature_base_string, "\n";

		$request->sign($self->_get_key);

		my $ua = LWP::UserAgent->new;

		my $res = $ua->request(GET($request->request_url, Authorization => $request->to_authorization_header));

		if (!$res->is_success) {
		    die 'Could not get feed: ' . $res->status_line . ' ' . $res->content;
		}

		my $parser = new XML::LibXML;
		my $doc = $parser->parse_string($res->content);
		my $xpc = XML::LibXML::XPathContext->new;
		$xpc->registerNs('atom', 'http://www.w3.org/2005/Atom');
		@contacts = shuffle($xpc->findnodes('//atom:entry/atom:title', $doc));

	}
	return $self->tt_process('default.html', {c => $self, contacts => \@contacts});
}

sub login : Runmode {
	my $self = shift;

	my $request = Net::OAuth->request("request token")->new(
	    $self->_default_request_params,
	    request_url => $self->config_param('request_token_endpoint'),
	    extra_params => {
		scope=> $self->config_param('request_scope'),
	    }
	);

	#print "base_string:", $request->signature_base_string, "\n";

	$request->sign($self->_get_key);

	my  $ua = LWP::UserAgent->new;

	my $res = $ua->request(GET $request->to_url); # Post message to the Service Provider

	if (!$res->is_success) {
	    die 'Could not get a Request Token: ' . $res->status_line . ' ' . $res->content;
	}

	my $response = Net::OAuth->response('request token')->from_post_body($res->content);
	print STDERR "Got Request Token ", $response->token, "\n";
	print STDERR "Got Request Token Secret ", $response->token_secret, "\n";

	$request = Net::OAuth->request('user auth')->new(
	    token => $response->token,
	    callback => $self->config_param('base_url') . "/callback",
	);

	return $self->_redirect($request->to_url($self->config_param('user_auth_endpoint')));
}
        
sub callback : Runmode {
	my $self = shift;
	my %params = $self->query->Vars;
	my $response = Net::OAuth->response('user auth')->from_hash(\%params);

	my $request = Net::OAuth->request("access token")->new(
	    $self->_default_request_params,
	    request_url => $self->config_param('access_token_endpoint'),
	    token => $response->token,
	    token_secret => '',
	);

	#print "base_string:", $request->signature_base_string, "\n";

	$request->sign($self->_get_key);

	my $ua = LWP::UserAgent->new;

	my $res = $ua->request(GET $request->to_url); # Post message to the Service Provider

	if (!$res->is_success) {
	    die 'Could not get an Access Token: ' . $res->status_line . ' ' . $res->content;
	}

	my $response = Net::OAuth->response('access token')->from_post_body($res->content);
	print STDERR "Got Access Token ", $response->token, "\n";
	print STDERR "Got Access Token Secret ", $response->token_secret, "\n";
	$self->session->param('token', $response->token);
	return $self->_redirect;
}

sub error_mode { "error_redirect" }

sub error_redirect {
	my $self = shift;
	my $error = shift;
	$self->session->param('errors', [$error]);
	if (not defined $ENV{PATH_INFO} or $ENV{PATH_INFO} =~ m,^/?$,) {
		return $error;
	}
	else {
		return $self->_redirect;
	}
}

sub logout : Runmode {
	my $self = shift;
	$self->session->clear('token');
	return $self->_redirect;
}

1;
