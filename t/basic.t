use Mojo::Base -strict;

use Test::More;
use Mojolicious::Lite;
use Test::Mojo;

plugin 'OAuth2::Wrapper' => {
  on_logout => 'logout',
  on_success => 'success',
  on_error => 'error',
  on_connect => [
    sub { warn 111; undef },
    sub { warn 222; 1 },
    #sub { shift->session(name => pop->{first_name}) },
    sub { warn Data::Dumper::Dumper(\@_) },
  ],
  providers => {mocked => {key => 42}},
};

get '/' => sub {
  my $c = shift;
  return $c->redirect_to('/connect/mocked') unless $c->session('id');
  return $c->reply->not_found unless $c->session('name');
  $c->render(inline => 'Welcome, <%= $c->session("name") %>');
} => 'index';

my $t = Test::Mojo->new;
$t->ua->max_redirects(10);
$t->get_ok('/')->status_is(200)->content_is('Welcome, f');

done_testing();
