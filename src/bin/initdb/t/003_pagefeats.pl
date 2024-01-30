# Copyright (c) 2024, PostgreSQL Global Development Group


use strict;
use warnings;
use Fcntl ':mode';
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

# validate expected handling of --page-feat

my $node1 = PostgreSQL::Test::Cluster->new('node1');
my $node2 = PostgreSQL::Test::Cluster->new('node2');

command_ok([ 'initdb', '--reserved-size=8', '--page-feat=foo=8', $node1->data_dir() ],
	'allocate exactly --reserved-size bytes for features');

command_ok([ 'initdb', '--reserved-size=8', '--page-feat=foo=1', $node2->data_dir() ],
	'allow underallocating page features');

my $feats = slurp_file($node2->data_dir() . "/pg_pagefeat/default");

ok(length($feats), 'wrote out page feature data');
ok($feats =~ m/foo=0,8/ms, 'rounded up underallocated page feature');

command_fails_like([ 'initdb', '--page-feat=foo=8', '-k' ],
    qr/\Qinitdb: error: cannot use page features and data_checksums at the same time\E/,
	'forbid checksums and page features from being used at the same time');

command_fails_like([ 'initdb', '--page-feat=foo=8', '--page-feat=foo=8' ],
    qr/\Qinitdb: error: duplicate page feature specified\E/,
	'fails on duplicate feature');

command_fails_like([ 'initdb', '--reserved-size=8', '--page-feat=foo=8', '--page-feat=foo2=8' ],
    qr/\Qinitdb: error: argument of --reserved-size must be at least as large as the initdb-time page feature selection (currently: 16)\E/,
	'fails when overallocating reserved-size');

command_fails_like([ 'initdb', '--page-feat=foo=200', '--page-feat=foo2=200' ],
    qr/\Qinitdb: error: couldn't add feature "foo2" of size "200" bytes\E/,
	'fails when overallocating max reserved size');

done_testing();
