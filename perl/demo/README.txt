OAUTH DEMO
==========

Dependencies
------------

Perl 5.8+

CGI::Application
CGI::Application::Plugin::AutoRunmode
CGI::Application::Plugin::TT
CGI::Application::Plugin::Session
CGI::Application::Plugin::Config::YAML
Net::OAuth
Crypt::OpenSSL::RSA
File::Slurp
Data::Random
LWP::UserAgent
HTTP::Request::Common
XML::LibXML

Registration
------------

You need to register your domain with Google, and generate a private key in PEM format.

See:

http://groups.google.com/group/oauth/browse_thread/thread/75ee6d973930c791/48f75bfdc1603b7c

Installation
------------

Super simple:

* Unzip files under the document root of a virtual host domain
* Edit settings in config.yml
** If you have mod_rewrite, the base_url should be http://mydomain.example.com
** If not, the base_url should be http://mydomain.example.com/oauth-demo.cgi

A little less simple:

* Put oauth-demo.cgi under your document root (say, in a cgi-bin)
* Set the OAUTH_DEMO_HOME environment variable to point to the dir containing all the other files
* Edit settings in config.yml
** Your base url will be the URL to the wherever you put oauth-demo.cgi
