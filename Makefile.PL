use strict;
use warnings;

use ExtUtils::MakeMaker;

WriteMakefile(
  NAME         => 'Mojolicious::Plugin::OAuth2::Wrapper',
  VERSION_FROM => 'lib/Mojolicious/Plugin/OAuth2/Wrapper.pm',
  AUTHOR       => 'A Good Programmer <nospam@cpan.org>',
  PREREQ_PM    => {'Mojolicious' => '7.03'},
  test         => {TESTS => 't/*.t'}
);
