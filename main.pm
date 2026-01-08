use strict;
use warnings;

use threads;
use threads::shared;

use HTTP::Status qw/is_client_error is_server_error/;
use JSON::PP;
use List::Util qw/reduce/;
use LWP::UserAgent;
use LWP::ConnCache;
use POSIX qw(setlocale LC_ALL);
use Time::Piece;
use File::Slurp qw(read_file);
use Crypt::JWT qw(encode_jwt);

use Data::Dumper;

# 日志常量
use constant {
	L_AUTH			=> 2,
	L_INFO			=> 3,
	L_ERR			=> 4,
	L_WARN			=> 5,
	L_PROXY			=> 6,
	L_ACCT			=> 7,
	L_DBG			=> 16,
};

# 返回码常量
use constant {
	RLM_MODULE_REJECT	=> 0,
	RLM_MODULE_FAIL		=> 1,
	RLM_MODULE_OK		=> 2,
	RLM_MODULE_HANDLED	=> 3,
	RLM_MODULE_INVALID	=> 4,
	RLM_MODULE_USERLOCK	=> 5,
	RLM_MODULE_NOTFOUND	=> 6,
	RLM_MODULE_NOOP		=> 7,
	RLM_MODULE_UPDATED	=> 8,
	RLM_MODULE_NUMCODES	=> 9,
};

use vars qw/%RAD_PERLCONF %RAD_REQUEST %RAD_REPLY %RAD_CHECK/;

my @sups;
my %realms :shared;

$ENV{LC_ALL} = 'C' unless (defined($ENV{LC_ALL}));

radiusd::radlog(L_DBG, 'oauth2 global init');

my $ua = LWP::UserAgent->new;
$ua->timeout(10);
$ua->env_proxy;
$ua->agent("freeradius-oauth2-perl/0.3 (+https://github.com/jimdigriz/freeradius-oauth2-perl; ${\$ua->_agent})");
$ua->conn_cache(LWP::ConnCache->new);
$ua->default_header('Accept-Encoding' => scalar HTTP::Message::decodable());

if (defined($RAD_PERLCONF{debug}) && $RAD_PERLCONF{debug} =~ /^(?:1|true|yes)$/i) {
	radiusd::radlog(L_INFO, 'debugging enabled, you will see the HTTPS requests in the clear!');
	sub debug_handler {
		my $r = $_[0]->clone;
		$r->decode;
		radiusd::radlog(L_DBG, $_) foreach split /\n/, $r->dump;
	}
	$ua->add_handler('request_send', \&debug_handler);
	$ua->add_handler('response_done', \&debug_handler);
}

if ($^V ge v5.28) {
	Time::Piece->use_locale();
}
use constant RADTIME_FMT => '%b %e %Y %H:%M:%S %Z';

sub to_radtime {
	my ($s) = @_;
	return Time::Piece->strptime($s, '%Y-%m-%dT%H:%M:%SZ')->strftime(RADTIME_FMT);
}

# 辅助函数：生成 OAuth2 Client Assertion (JWT)
sub _generate_assertion {
	my ($client_id, $token_endpoint, $key_path) = @_;
	
	unless (-f $key_path) {
		radiusd::radlog(L_ERR, "oauth2: private key file not found at $key_path");
		return undef;
	}

	my $private_key_data = read_file($key_path);
	
	return encode_jwt(
		payload => {
			iss => $client_id,
			sub => $client_id,
			aud => $token_endpoint,
			jti => time() . rand(),
			exp => time() + 300, # 5分钟有效期
		},
		key => \$private_key_data,
		alg => 'RS256'
	);
}

sub worker {
	my $thr;
	my $running = 1;
	$SIG{'HUP'} = sub { $thr->kill('TERM') if (defined($thr)); };
	$SIG{'TERM'} = sub { $running = 0; $thr->kill('TERM') if (defined($thr)); };

	setlocale(LC_ALL, $ENV{LC_ALL});

	# 接收新增的证书路径参数
	our ($realm, $discovery_uri, $client_id, $client_secret, $client_key_path) = @_;
	our $ttl = int($RAD_PERLCONF{ttl} || 30);
	$ttl = 10 if ($ttl < 10);

	our $graph_origin;
	if (rindex($discovery_uri, 'https://login.microsoftonline.us/', 0) == 0) {
		$graph_origin = 'graph.microsoft.us';
	} elsif (rindex($discovery_uri, 'https://login.chinacloudapi.cn/', 0) == 0) {
		$graph_origin = 'microsoftgraph.chinacloudapi.cn';
	} else {
		$graph_origin = 'graph.microsoft.com';
	}

	radiusd::radlog(L_DBG, "oauth2 worker ($realm): fetching discovery");
	my $r = $ua->get("${discovery_uri}/.well-known/openid-configuration");
	unless ($r->is_success) {
		radiusd::radlog(L_ERR, "oauth2 worker ($realm): discovery failed: ${\$r->status_line}");
		die "discovery ($realm) failed";
	}
	our $discovery = decode_json $r->decoded_content;

	my $pacing = 0;
	while (1) {
		$thr = async {
			my $running = 1;
			$SIG{'TERM'} = sub { $running = 0; };
			setlocale(LC_ALL, $ENV{LC_ALL});

			our ($authorization_var, $authorization_ttl);
			
			sub authorization {
				return $authorization_var if (defined($authorization_var) && $authorization_ttl > time());

				radiusd::radlog(L_DBG, "oauth2 worker ($realm): requesting client_credentials token");

				my %params = (
					client_id  => $client_id,
					scope      => "https://${graph_origin}/.default",
					grant_type => 'client_credentials',
				);

				# 证书验证逻辑
				if ($client_key_path ne '') {
					my $assertion = _generate_assertion($client_id, $discovery->{token_endpoint}, $client_key_path);
					if ($assertion) {
						$params{client_assertion_type} = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
						$params{client_assertion} = $assertion;
					} else {
						$params{client_secret} = $client_secret;
					}
				} else {
					$params{client_secret} = $client_secret;
				}

				my $r = $ua->post($discovery->{token_endpoint}, \%params);
				unless ($r->is_success) {
					radiusd::radlog(L_ERR, "oauth2 worker ($realm): token failed: ${\$r->status_line}");
					return;
				}

				my $token = decode_json $r->decoded_content;
				$authorization_var = "${\$token->{token_type}} ${\$token->{access_token}}";
				$authorization_ttl = time() + $token->{expires_in} - 60; # 提前1分钟过期

				return $authorization_var;
			}

			sub fetch {
				my ($purpose, $uri) = @_;
				my $r = $ua->get($uri, Authorization => &authorization(), Prefer => 'return=minimal', Accept => 'application/json');
				if (!$r->is_success && $r->code == HTTP::Status::HTTP_UNAUTHORIZED) {
					$authorization_var = undef;
					return &fetch($purpose, $uri);
				}
				return $r->is_success ? decode_json($r->decoded_content) : undef;
			}

			sub walk {
				my ($purpose, $uri, $callback) = @_;
				my $delta;
				while (defined($uri)) {
					my $data = &fetch($purpose, $uri);
					last unless $data;
					&$callback($data->{value});
					$delta = $data->{'@odata.deltaLink'};
					$uri = $data->{'@odata.nextLink'};
				}
				return $delta;
			}

			my (%users, %groups);
			my $usersUri = "https://${graph_origin}/v1.0/users/delta?\$select=id,userPrincipalName,isResourceAccount,accountEnabled,lastPasswordChangeDateTime";
			my $groupsUri = "https://${graph_origin}/v1.0/groups/delta?\$select=id,displayName,members";

			while ($running) {
				radiusd::radlog(L_INFO, "oauth2 worker ($realm): sync start");
				$usersUri = &walk('users', $usersUri, sub {
					my ($data) = @_;
					foreach my $d (grep { ($_->{isResourceAccount} || JSON::PP::false) != JSON::PP::true } @$data) {
						my $id = $d->{id};
						if (exists($d->{'@removed'})) { delete $users{$id}; }
						else {
							my $r = $users{$id} //= shared_clone({});
							$r->{n} = $d->{userPrincipalName} if exists $d->{userPrincipalName};
							$r->{e} = ($d->{accountEnabled} == JSON::PP::true) if exists $d->{accountEnabled};
							$r->{p} = to_radtime($d->{lastPasswordChangeDateTime}) if exists $d->{lastPasswordChangeDateTime};
						}
					}
				});

				$groupsUri = &walk('groups', $groupsUri, sub {
					my ($data) = @_;
					foreach my $d (@$data) {
						my $id = $d->{id};
						if (exists($d->{'@removed'})) { delete $groups{$id}; }
						else {
							my $r = $groups{$id} //= shared_clone({m => shared_clone({})});
							$r->{n} = $d->{displayName} if exists $d->{displayName};
							foreach (@{$d->{'members@delta'}}) {
								if (exists $_->{'@removed'}) { delete $r->{m}->{$_->{id}}; }
								else { $r->{m}->{$_->{id}} = undef; }
							}
						}
					}
				});

				my %db :shared;
				$db{t} = $discovery->{token_endpoint};
				$db{u} = shared_clone({});
				foreach (keys %users) {
					my $u = $users{$_};
					$db{u}{lc $u->{n}} = $u->{p} if $u->{n} && $u->{e};
				}
				$db{g} = shared_clone({});
				foreach (keys %groups) {
					my $g = $groups{$_};
					my @m = map { lc $users{$_}->{n} } grep { $users{$_} && $users{$_}->{e} } keys %{$g->{m}};
					$db{g}->{$g->{n}} = shared_clone({ map { $_, undef } @m }) if @m;
				}

				{
					lock(%{$realms{$realm}});
					%{$realms{$realm}} = %db;
					cond_signal(%{$realms{$realm}});
				}
				$pacing = 0;
				my $sleep = int($ttl * 0.7 + rand($ttl * 0.6));
				sleep($sleep);
			}
		};

		$thr->join();
		last unless $running;
		sleep($pacing++ ** 2);
	}
}

sub authorize {
	my $username = $RAD_REQUEST{'User-Name'};
	my $realm = $RAD_REQUEST{'Realm'};
	return RLM_MODULE_INVALID unless (defined($username) && defined($realm));

	{
		lock(%realms);
		unless (exists($realms{$realm})) {
			my $discovery_uri = radiusd::xlat("%{config:realm[$realm].oauth2.discovery}");
			my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
			my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
			# 新增：证书路径
			my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");

			return RLM_MODULE_FAIL if ($client_id eq '');

			$realms{$realm} = shared_clone({});
			lock(%{$realms{$realm}});
			push @sups, threads->create(\&worker, $realm, $discovery_uri, $client_id, $client_secret, $client_key_path);
			cond_wait(%{$realms{$realm}});
		}
	}

	my $state;
	{ lock(%{$realms{$realm}}); $state = $realms{$realm}; }
	return RLM_MODULE_NOTFOUND unless (exists($state->{u}{lc $username}));

	$RAD_REQUEST{'OAuth2-Group'} = reduce { push @$a, $b if (exists($state->{g}{$b}{lc $username})); $a; } [], keys %{$state->{g}};
	$RAD_CHECK{'OAuth2-Password-Last-Modified'} = $state->{u}{lc $username};
	$RAD_CHECK{'Auth-Type'} = 'oauth2';

	return RLM_MODULE_UPDATED;
}

sub authenticate {
	my $username = $RAD_REQUEST{'User-Name'};
	my $realm = $RAD_REQUEST{'Realm'};

	my $state;
	{ lock(%{$realms{$realm}}); $state = $realms{$realm}; }

	my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
	my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
	my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");

	my %params = (
		client_id  => $client_id,
		scope      => 'openid email',
		grant_type => 'password',
		username   => $username,
		password   => $RAD_REQUEST{'User-Password'}
	);

	# 证书验证逻辑
	if ($client_key_path ne '') {
		my $assertion = _generate_assertion($client_id, $state->{t}, $client_key_path);
		if ($assertion) {
			$params{client_assertion_type} = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
			$params{client_assertion} = $assertion;
		} else {
			$params{client_secret} = $client_secret;
		}
	} else {
		$params{client_secret} = $client_secret;
	}

	my $r = $ua->post($state->{t}, \%params);
	unless ($r->is_success) {
		radiusd::radlog(L_ERR, "oauth2 token failed: ${\$r->status_line}");
		return RLM_MODULE_FAIL if (is_server_error($r->code));
		my $resp = decode_json $r->decoded_content;
		$RAD_REPLY{'Reply-Message'} = $resp->{error_description} // $resp->{error};
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

sub detach {
	# Cleanup
}

1;
