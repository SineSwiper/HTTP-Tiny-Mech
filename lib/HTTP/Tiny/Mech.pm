use v5.10;
use strict;
use warnings;

package HTTP::Tiny::Mech;

# ABSTRACT: Wrap a WWW::Mechanize instance in an HTTP::Tiny compatible interface.

use Moose;
use MooseX::NonMoose;
use HTTP::Date ();
extends 'HTTP::Tiny';

has 'mechua' => (
  is   => 'rw',
  isa  => 'Object',
  required => 1,
  # BUILDARGS already does the defaulting
);

=head1 SYNOPSIS

  # Get something that expects an HTTP::Tiny instance
  # to work with WWW::Mechanize under the hood.
  #
  my $thing => ThingThatExpectsHTTPTiny->new(
    ua => HTTP::Tiny::Mech->new()
  );

  # Get something that expects HTTP::Tiny
  # to work via WWW::Mechanize::Cached
  #
  my $thing => ThingThatExpectsHTTPTiny->new(
    ua => HTTP::Tiny::Mech->new(
      mechua => WWW::Mechanize::Cached->new( )
    );
  );
  # -OR-
  my $thing => ThingThatExpectsHTTPTiny->new(
    ua => HTTP::Tiny::Mech->new(
      mechua_class => 'WWW::Mechanize::Cached',
      cache => $cache,
      # ...insert either HTTP::Tiny or
      # WWW::Mechanize::Cached options here...
      mechua_use_tiny_defaults => 0,  # default is ON
    );
  );
  
  
=cut

=head1 DESCRIPTION

This code started out as a quick bit of hacking to get L<MetaCPAN::API>
working faster via the L<WWW::Mechanize::Cached> module (and gaining cache
persistence via L<CHI>).  It works so far for this purpose.

At this time, all methods should work to utilize the C<mechua> object for
all web requests.  Most of the magic happens by overloading C<_request>,
and letting L<HTTP::Tiny>'s other methods call the overload.

=head1 CONSTRUCTOR ARGUMENTS
 
The following arguments are available to pass to the C<new> method:

=head2 mechua

This is a L<WWW::Mechanize> or compatible object.  If passed, it will be used
as the user agent object that the rest of the methods will use.  Technically,
this object could also be a L<LWP::UserAgent> or compatible one as well, but
this isn't guaranteed work in the future.

If this or C<mechua_class> aren't specified, a L<WWW::Mechanize> object will
be created for you.

=head2 mechua_class

This is a class string for a L<WWW::Mechanize> compatible class.  By default,
this is C<WWW::Mechanize>.  The object will be created for you during
construction, and can be accessed via C<$self->mechua>.

This style is handy if you want the constructor to translate the HTTP::Tiny
arguments for you, but still want to use a different class.

=head2 mechua_use_tiny_defaults

This boolean indicates if the L<HTTP::Tiny> constructor defaults should be
used.  By default, this is true.  If you pass a C<mechua> object and this 
is on, it will set the defaults that differ between the two as attribute
sets.  Currently, these are:

   max_redirect = 5  (vs. 7   on LWP)
   timeout      = 60 (vs. 180 on LWP)
   verify_SSL   = no SSL verification at all (vs. header verify on LWP)

=head2 ...any HTTP::Tiny argument...

These arguments will be automatically translated to L<WWW::Mechanize>
compatible ones.

=head2 ...any WWW::Mechanize argument...

These arguments will be simply be passed through to the C<mechua> creation.

Please note that if the UA already exists (via a passed C<mechua> argument),
all other arguments are converted to "post-construction attribute sets",
which will call C<$mechua->$key($val)> for each argument.

=cut

after BUILDARGS {  # let Moose::Object handle the hashification
   my ($class, $args) = @_;
   my $tiny_defaults = $args->{mechua_use_tiny_defaults} // 1;
   delete $args->{mechua_use_tiny_defaults};

   # translate HTTP::Tiny-related arguments to WWW::Mechanize ones
   my $post_attrs = {};
   foreach my $key (sort keys %$args) {  # sorting only matters for ssl_opts
      my $val = $args->{$key};
      
      # direct passthru: agent, local_address, max_redirect, max_size
      for ($key) {
         when ('default_headers') {
            require HTTP::Headers;
            $args->{$key} = HTTP::Headers->new($val);
         }
         when ('proxy') {
            $post_attrs->{proxy} = [ 'http', delete $args->{$key} ];
            $args->{noproxy} //= 1;
         }
         when ('SSL_options') {
            $args->{ssl_opts} //= {};
            $args->{ssl_opts} = {
               %{$args->{ssl_opts}},
               %{delete $args->{$key}},
            };
         }
         when ('verify_SSL') {
            $args->{ssl_opts} //= {};
            $args->{ssl_opts} = {
               $args->{$key} ? (
                  verify_hostname     => 1,
                  SSL_verifycn_scheme => 'http',
                  SSL_verify_mode     => 0x01,
                  SSL_ca_file         => HTTP::Tiny::_find_CA_file(),
               ) : (
                  SSL_verifycn_scheme => 'none',
                  SSL_verify_mode     => 0x00,
               ),
               %{$args->{ssl_opts}},  # specific ssl_opts trumps verify_SSL
            };
            # we'll delete verify_SSL later...
         }
      }
   }
   
   # HTTP::Tiny defaults
   if ($tiny_defaults) {
      $args->{max_redirect} //= 5;
      $args->{timeout}      //= 60;
      unless (exists $args->{verify_SSL}) {
         $args->{ssl_opts} //= {};
         $args->{ssl_opts} = {
            SSL_verifycn_scheme => 'none',
            SSL_verify_mode     => 0x00,
            %{$args->{ssl_opts}},  # specific ssl_opts trumps verify_SSL
         };
      }
   }
   delete $args->{verify_SSL};

   # handle the different mechua* arguments
   my $mechua;
   if ($mechua = delete $args->{mechua}) {
      die "Cannot pass both a mechua object and a mechua_class param!"
         if $args->{mechua_class};
      
      # Since the object is already created, these arguments turn into
      # post-attribute sets.
      $post_attrs = {
         %$post_attrs,
         %$args,
      };
      $args = {};
      
      # We might set noproxy, which doesn't actually exist, so translate
      # it to the right method
      $post_attrs->{env_proxy} = [] if delete $post_attrs->{noproxy};
      # The rest of the HTTP::Tiny arguments passthru fine, and we're
      # not translating WWW::Mechanize arguments, since they already 
      # have access to that.
   }
   else {
      # now, move all of those arguments into a WWW::Mechanize(-ish) object
      # and throw them away...
      my $class = delete $args->{mechua_class} || 'WWW::Mechanize';
      
      use Module::Load;
      load $class;
      $mechua = $class->new(%$args);
   }
   
   # run through post-attribute sets
   no strict 'refs';
   foreach my $method (keys %$post_attrs) {
      my $param  = $post_attrs->{$method};
      my @params = ref $param eq 'HASH'  ? @$param :
                   ref $param eq 'ARRAY' ? %$param :
                   defined $param        ? ($param) : ();

      $mechua->$method(@params) if $mechua->can($method);
   }
   
   return {
      mechua => $mechua,
   };
}

sub _unwrap_response {
  my ( $self, $response ) = @_;
  
  # convert HTTP::Headers to hashref of scalar/arrayrefs
  my $headers = {};
  $response->headers->scan( sub { 
    my ($f, $v) = @_;
    my $e = $headers->{$f};
    $e ?  
      ref $e ? push(@$e, $v) : $headers->{$f} = [ $e, $v ] :
      $headers->{$f} = $v;
  } );
  
  return {
    url     => $response->request->uri->as_string,
    status  => $response->code,
    reason  => $response->message,
    headers => $headers,
    success => $response->is_success,
    content => $response->content,
  };
}

sub _wrap_request {
  my ( $self, $method, $uri, $opts ) = @_;
  require HTTP::Request;
  my $req = HTTP::Request->new( $method, $uri );
  $req->headers( $opts->{headers} ) if $opts->{headers};
  $req->content( $opts->{content} ) if $opts->{content};
  
  # Handle callbacks
  $self->mechua->set_my_handler(request_prepare => sub {
    my ($request, $ua, $h) = @_;
    $request->header( %{ $opt->{trailer_callback}->() } );
  }) if (defined $opts->{content} && $opts->{trailer_callback});  # filtering rules according to HTTP::Tiny::_prepare_headers_and_cb

  $self->mechua->set_my_handler(response_data => sub {
    my ($response, $ua, $h, $data) = @_;
    # according to HTTP::Tiny::_prepare_data_cb, must be successful
    return 1 unless ($response->is_success);
    
    # unfortunately, none of HTTP::Tiny's interfaces are objects or refs,
    # so this is purely read-only...
    my $tiny_res = $self->_unwrap_response($response);
    $opt->{data_callback}->(
      $data,
      $tiny_res,
    );
    
    return 1;
  }) if ($opts->{data_callback});
  
  return $req;
}

sub _agent {
  return __PACKAGE__."/$VERSION ".$_[0]->_agent;
}

# (Quit adapting; start using...)
sub _http_date       { HTTP::Date::time2str  ($_[1]); }
sub _parse_http_date { HTTP::Date::parse_date($_[1]); }

### HTTP::Tiny->get|post|etc will call its ->request ###
### HTTP::Tiny->post_form    will call its ->request & our $self->www_form_urlencode ###
### HTTP::Tiny->mirror       will call its ->request ###
### HTTP::Tiny->request      will call our $self->_request ###

sub _request {
  my $self     = shift;
  my $req      = $self->_wrap_request(@_);
  my $response = $self->mechua->request($req);
  
  # clear callbacks
  $self->mechua->set_my_handler(request_prepare => undef);
  $self->mechua->set_my_handler(response_data   => undef);
  
  return $self->_unwrap_response($response);
}

sub www_form_urlencode {
  my ( $self, $content ) = @_;
  
  # We use a temporary URI object to format
  # the application/x-www-form-urlencoded content.
  # (Exactly like HTTP::Request::Common...)
  require URI;
  my $url = URI->new('http:');
  $url->query_form(ref($content) eq "HASH" ? %$content : @$content);
  return $url->query;
}

__PACKAGE__->meta->make_immutable;
no Moose;

1;
