package Mojolicious::Plugin::OAuth2::Wrapper;
use Mojo::Base 'Mojolicious::Plugin';

our $VERSION = '0.01';

# scope is the OAuth2 way of presenting to the service what portion of the user's data you're interested in reading
#   the service will ask the user to approve authorization and tell the user the data components your application is asking to read
# fetch_user_url is the URL that the application needs to query in order to get access to the requested data components
# map provides an easy mechanism to the application uniformly making data from different systems available by the same name.
#   Mojo::JSON::Pointer is used to allow for new provider plugins and mapping them to a uniform name.
#   For example this made up JSON data object from Google: {"custom":{"deeper":{"my_first_name":"John"}}}
#   And this made up JSON data object from Facebook: {"buried":{"somewhere":[{"the_given_name":"Sam"}]}}
#   You can now create a custom provider (via config file) and make the first name available from Google and Facebook to your application in a uniform way:
#   Google: first_name => '/custom/deeper/my_first_name'
#   Facebook: first_name => '/buried/somewhere/0/the_given_name'
#   Notice that now whether using Google or Facebook, we can access the first name with first_name
#   NB: Since your app has control over these Provider definitions, you have control over the map.  You can choose what data from a Provider goes into what values
#       As such, you can choose to have no uniformity, but it's not recommended.
has providers => sub {
  return {
    mocked => {
      args => {
        scope => 'user_about_me email',
      },
      fetch_user_url => '/mocked/me?access_token=%token%',
      map => {
        error => '/err/0',
        id => '/i',
        email => '/e',
        first_name => '/f',
        last_name => '/l',
      },
    },
    facebook => {
      args => {
        scope => 'public_profile email',
      },
      fetch_user_url => 'https://graph.facebook.com/v2.6/me?fields=email,first_name,last_name&access_token=%token%',
      map => {
        error => '/error/message',
        id => '/id',
        email => '/email',
        first_name => '/first_name',
        last_name => '/last_name',
      },
    },
    google => {
      args => {
        scope => 'profile email' ,
      },
      fetch_user_url => 'https://www.googleapis.com/plusDomains/v1/people/me?access_token=%token%',
      map => {
        error => '/error/message',
        id => '/id',
        email => '/emails/0/value',
        first_name => '/name/givenName',
        last_name => '/name/familyName',
      },
    },
  }
};

sub register {
  my ($self, $app, $config) = @_;
  my $oauth2_config = {};

  # Die unless the four required Plugin config values are defined
  die unless ref $config eq 'HASH';
  die unless $config->{on_logout} && $config->{on_success} && $config->{on_error} && $config->{on_connect};
  ref $config->{$_} and die for qw/on_logout on_success on_error/;
  die unless ref $config->{on_connect} eq 'ARRAY';

  # Here we're merging the Provider configurations from the built-in ones above and those passed in via Plugin configuration
  my $providers = $self->providers;
  foreach my $provider (keys %{$config->{providers}}) {
    if (exists $providers->{$provider}) {
      foreach my $key (keys %{$config->{providers}->{$provider}}) {
        $providers->{$provider}->{$key} = $config->{providers}->{$provider}->{$key};
      }
    }
    else {
      $providers->{$provider} = $config->{providers}->{$provider};
    }
  }
  $self->providers($providers);

  # This is the OAuth2 plugin that we're wrapping for -- this is the real OAuth2 plugin
  $app->plugin("OAuth2" => { fix_get_token => 1, %{$config->{providers}} });

  # Provide a logout endpoint that wipes the user session
  # After logout, redirect to the Mojolicious route defined in this Plugin's configuration on_logout value
  $app->routes->get('/logout' => sub {
    my $c = shift;
    my $token = $c->session('token') || {};
    delete $c->session->{$_} foreach keys %{$c->session};
    $token->{$_} = {} foreach keys %$token;
    $c->session(token => $token);
    $c->redirect_to($config->{on_logout});
  })->name('logout');
  
  # I don't think this is necessary
  #$app->routes->get('/account/:provider' => {provider => ''} => sub {
  #  my $c = shift;
  #  #return $c->render($c->session('id') ? 'logout' : 'login') unless $c->param('provider');
  #  return $c->reply->not_found unless $c->param('provider');
  #  return $c->redirect_to('connectprovider', {provider => $c->param('provider')}) ; #removed "unless $c->session('id')"
  #  $c->redirect_to($config->{on_success});
  #})->name('account');

  # A mock built-in service for testing OAuth2 without bothering with creating the necessary definition within a real Provider's web panel
  $app->routes->get("/mocked/me" => sub {
    my $c = shift;
    my $access_token = $c->param('access_token');
    return $c->render(json => {err => ['Invalid access token']}) unless $access_token eq 'fake_token';
    $c->render(json => { i => 123, f => 'a', l => 'a', e => 'a@a.com' });
  });

  # This is where the wrapper wraps
  $app->routes->get("/connect/:provider" => sub {
    my $c = shift;
    $c->session('token' => {}) unless $c->session('token');
    my $provider = $c->param('provider');
    my $token = $c->session('token');
    my ($success, $error, $connect) = ($config->{on_success}, $config->{on_error}, $config->{on_connect});
    my ($args, $fetch_user_url, $map) = ($self->providers->{$provider}->{args}, $self->providers->{$provider}->{fetch_user_url}, {%{$self->providers->{$provider}->{map}}});

    $c->delay(
      sub {   
        my $delay = shift;
        # Only get the token from $provider if the current one isn't expired
        # Either way, move on to the next sub
        # In other words, if the token (in $c->session) isn't expired then move on
        if ( $token->{$provider} && $token->{$provider}->{access_token} && $token->{$provider}->{expires_at} && time < $token->{$provider}->{expires_at} ) {
          my $cb = $delay->begin;
          $c->$cb(undef, $token->{$provider}); 
        # Otherwise, connect to the Provider and let them know the URL that you want the Provider to connect you back to after getting authorization from the user
        } else {        
          my $args = {redirect_uri => $c->url_for('connectprovider', {provider => $provider})->userinfo(undef)->to_abs, %$args};
          # QUESTION: Should this line be here, it's forcing the app to listen on https; can it work without?  Setting up SSL for test sites is a pain
          #$args->{redirect_uri} =~ s/^http/https/;
          $c->oauth2->get_token($provider => $args, $delay->begin);
        }
      },
      # At this point we either have a token from a previous transaction and it hasn't expired or we've just obtain a new token from the Provider
      sub {
        # If already connected to $provider, no reason to go through this again
        # All this does is pull down basic info / email and store locally
        my ($delay, $err, $data) = @_;
warn Data::Dumper::Dumper $data;        
        # There are three ways to use this sub; that is a first-time OAuth2 transaction will pass through this sub 3 times

        # Do we already have an id in session (in other words, already logged in?) and does on_connect agree that it's a valid id?
        return $c->redirect_to($success) if $connect->[0]->($c, $c->session('id'), $provider); # on_connect Form #1

        # If no id in session, we need to connect to the Provider and look it up

        # Check out the token received from the Provider and if it's good save it to the session
        # We save the token to bypass all these steps if the token hasn't expired and if we have a valid session id
        unless ( $data->{access_token} ) {
          $c->flash(error => "Could not obtain access token: $err");
          return $c->redirect_to($error);
        }
        $token->{$provider} = $data;
        $token->{$provider}->{expires_at} = time + ($token->{$provider}->{expires_in}||3600);
        $c->session(token => $token);

        # User has authorized the application's request to access a portion of their data and the Provider gave a quality token meaning the user authorized the request
        # Now it's time to get the data from the Provider -- what we really care about (and why we're using OAuth2) such as the user's name and email address
        $c->ua->get($self->_fetch_user_url($fetch_user_url, $token->{$provider}->{access_token}), sub {
          my ($ua, $tx) = @_;
          return $c->reply->exception("No JSON response") unless defined $tx->res->json;
          my $json = Mojo::JSON::Pointer->new($tx->res->json);
          # If the data returned from the Provider contains an error then redirect to the on_error handler
          # The received error message will be available to the on_error handler via flash
          if ( my $error_message = $json->get(delete $map->{error}) ) {
            $c->flash(error => $error_message);
            return $c->redirect_to($error);
          }
          # Retrieve the id from the Provider, let on_connect process it (for storing in a database most likely) and save it in the session
          $c->session(id => $connect->[1]->($c, $json->get($map->{id}))) unless $c->session('id'); # on_connect Form #2
          # Get the rest of the data and let on_connect process it (for storing in a database most likely)
          $connect->[2]->($c, $c->session('id'), $provider, $tx->res->json, {map { $_ => $json->get($map->{$_}) } keys %$map}); # on_connect Form #3
          # Got the data, stored it, and have a valid session ID from the Provider.  We're officially logged in and have access to the desired info (via session, and from wherever on_connect stored the data long-term (database))
          # Redirect to the on_success handler
          $c->redirect_to($success);
        });
      },
    );
  });
}

sub _fetch_user_url {
  my ($self, $fetch_user_url, $token) = @_;
  $fetch_user_url =~ s/%token%/$token/g;
  return $fetch_user_url;
}

1;
__END__

=encoding utf8

=head1 NAME

Mojolicious::Plugin::OAuth2::Wrapper - Mojolicious OAuth2 Wrapper Plugin

=head1 SYNOPSIS

  use Mojolicious::Lite;

  # Mojolicious::Lite
  plugin 'OAuth2::Wrapper' => {
    # These must be valid Mojolicious routes.
    on_logout => 'index',
    on_success => 'index',
    on_error => 'error',
    # There are up to 3 steps in the OAuth2 connection process and you need to provider handler code for each step
    on_connect => [
      # Lookup the id that is in session and return it if valid, return undef if the id in session needs to be refreshed
      sub {
        my ($c, $id_from_session, $provider_name) = @_;
        # ... do something with the $id_from_session (like look it up in the database)
        return $id_from_session || undef;
      },
      # Pull the id from the Provider and save it to the session
      sub {
        my ($c, $id_from_provider) = @_;
        # ... do something with the $id (like store it in a database)
        return $id_from_provider;
      },
      # Pull the rest of the requested data from the Provider and store it uniformly in the session
      # In this way, no matter which Provider the user is connecting through, the app can get access to the data in the same way (such as email address)
      sub {
        my ($c, $id, $provider_name, $json_data_from_provider, $normalized_data_from_provider) = @_;
        # ... do something with the $normalized_data_from_provider (like store it in a database)
        $c->session->{name} = $normalized_data_from_provider->{first_name};
        $c->flash(message => "Welcome, $normalized_data_from_provider->{email}");
      }
    ],
    # This is necessary as it provides the Provider key and secrets
    providers => app->config->{oauth2},
  };

  # Carry on with your app
  get '/' => sub {
    my $c = shift;
    return $c->redirect_to('/connect/google') unless $c->session('id');
    return $c->reply->not_found unless $c->session('name');
    $c->render(inline => 'Welcome, <%= $c->session('name') %>');
  } => 'index';

=head1 DESCRIPTION

L<Mojolicious::Plugin::OAuth2::Wrapper> is a L<Mojolicious> plugin.

=head1 METHODS

L<Mojolicious::Plugin::OAuth2::Wrapper> inherits all methods from
L<Mojolicious::Plugin> and implements the following new ones.

=head2 register

  $plugin->register(Mojolicious->new);

Register plugin in L<Mojolicious> application.

=head1 SEE ALSO

L<Mojolicious>, L<Mojolicious::Guides>, L<http://mojolicio.us>.

