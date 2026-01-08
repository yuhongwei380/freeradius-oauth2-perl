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
use MIME::Base64 qw(decode_base64 encode_base64url);
use Digest::SHA qw(sha1);

use Data::Dumper;

use constant {
	L_AUTH			=> 2,
	L_INFO			=> 3,
	L_ERR			=> 4,
	L_WARN			=> 5,
	L_PROXY			=> 6,
	L_ACCT			=> 7,
	L_DBG			=> 16,
};

use constant {
	RLM_MODULE_REJECT	=>  0,
	RLM_MODULE_FAIL		=>  1,
	RLM_MODULE_OK		=>  2,
	RLM_MODULE_HANDLED	=>  3,
	RLM_MODULE_INVALID	=>  4,
	RLM_MODULE_USERLOCK	=>  5,
	RLM_MODULE_NOTFOUND	=>  6,
	RLM_MODULE_NOOP		=>  7,
	RLM_MODULE_UPDATED	=>  8,
	RLM_MODULE_NUMCODES	=>  9,
};

use vars qw/%RAD_PERLCONF %RAD_REQUEST %RAD_REPLY %RAD_CHECK/;

my @sups;
my %realms :shared;

$ENV{LC_ALL} = 'C' unless (defined($ENV{LC_ALL}));

radiusd::radlog(L_DBG, 'oauth2 global');

my $ua = LWP::UserAgent->new;
$ua->timeout(10);
$ua->env_proxy;
$ua->agent("freeradius-oauth2-perl/0.2 (+https://github.com/jimdigriz/freeradius-oauth2-perl; ${\$ua->_agent})");
$ua->conn_cache(LWP::ConnCache->new);
$ua->default_header('Accept-Encoding' => scalar HTTP::Message::decodable());

if (defined($RAD_PERLCONF{debug}) && $RAD_PERLCONF{debug} =~ /^(?:1|true|yes)$/i) {
	radiusd::radlog(L_INFO, 'debugging enabled, you will see the HTTPS requests in the clear!');
	sub handler {
		my $r = $_[0]->clone;
		$r->decode;
		radiusd::radlog(L_DBG, $_) foreach split /\n/, $r->dump;
	}
	$ua->add_handler('request_send', \&handler);
	$ua->add_handler('response_done', \&handler);
}

if ($^V ge v5.28) {
	Time::Piece->use_locale();
} else {
	warn "old version of Perl (pre-5.28) detected";
}
use constant RADTIME_FMT => '%b %e %Y %H:%M:%S %Z';
sub to_radtime {
	my ($s) = @_;
	return Time::Piece->strptime($s, '%Y-%m-%dT%H:%M:%SZ')->strftime(RADTIME_FMT);
}

# --- 辅助函数: 计算证书指纹 (x5t) ---
sub get_cert_thumbprint {
    my ($file_path) = @_;
    
    unless (-f $file_path) {
        radiusd::radlog(L_ERR, "oauth2: Certificate file not found at $file_path");
        return undef;
    }

    my $content = read_file($file_path);
    
    # 提取证书部分 (适配 PEM 格式)
    my ($cert_body) = $content =~ /-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s;
    unless ($cert_body) {
        # 尝试直接处理可能是 DER 格式或者是没有 header 的 base64
        # 但通常 PEM 都有 header，如果没有匹配到，尝试直接用整个文件内容（容错）
        $cert_body = $content; 
    }
    
    # 去除头尾和换行符，解码 Base64
    $cert_body =~ s/-----BEGIN CERTIFICATE-----//g;
    $cert_body =~ s/-----END CERTIFICATE-----//g;
    $cert_body =~ s/\s+//g;
    
    my $der = eval { decode_base64($cert_body) };
    if ($@ || !$der) {
        radiusd::radlog(L_ERR, "oauth2: Failed to decode certificate base64 from $file_path");
        return undef;
    }
    
    # 计算 SHA-1 哈希
    my $digest = sha1($der);
    
    # 返回 Base64Url 编码
    return encode_base64url($digest);
}

# --- 辅助函数: 生成 Client Assertion JWT ---
# 参数增加: cert_path
sub generate_client_assertion {
    my ($client_id, $token_endpoint, $key_path, $cert_path) = @_;
    
    unless (-f $key_path) {
        radiusd::radlog(L_ERR, "oauth2: Key file not found at $key_path");
        return undef;
    }

    # 使用证书文件计算 x5t
    my $x5t = get_cert_thumbprint($cert_path);
    unless ($x5t) {
        radiusd::radlog(L_ERR, "oauth2: Failed to calculate x5t thumbprint from $cert_path");
        return undef;
    }

    my $jwt;
    eval {
        my $private_key = read_file($key_path);
        my $now = time();
        my $payload = {
            aud => $token_endpoint,
            iss => $client_id,
            sub => $client_id,
            jti => "id" . $now . int(rand(10000)),
            nbf => $now,
            iat => $now,
            exp => $now + 300, 
        };
        
        $jwt = encode_jwt(
            payload       => $payload,
            key           => \$private_key,
            alg           => 'RS256',
            extra_headers => { x5t => $x5t } # 关键点：将指纹放入 Header
        );
    };
    if ($@) {
        radiusd::radlog(L_ERR, "oauth2: JWT Generation Error: $@");
        return undef;
    }
    return $jwt;
}

sub worker {
	my $thr;
	my $running = 1;
	$SIG{'HUP'} = sub { print STDERR "worker supervisor SIGHUP\n"; $thr->kill('TERM') if (defined($thr)); };
	$SIG{'TERM'} = sub { print STDERR "worker supervisor SIGTERM\n"; $running = 0; $thr->kill('TERM') if (defined($thr)); };

	setlocale(LC_ALL, $ENV{LC_ALL});

    # 接收参数增加 $client_cert_path
	our ($realm, $discovery_uri, $client_id, $client_secret, $client_key_path, $client_cert_path) = @_;
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

	radiusd::radlog(L_DBG, "oauth2 worker ($realm): supervisor started (tid=${\threads->tid()})");
	
	my $r = $ua->get("${discovery_uri}/.well-known/openid-configuration");
	unless ($r->is_success) {
		radiusd::radlog(L_ERR, "oauth2 worker ($realm): discovery failed: ${\$r->status_line}");
		die "discovery ($realm): ${\$r->status_line}";
	}
	our $discovery = decode_json $r->decoded_content;

	my $pacing = 0;
	while (1) {
		$thr = async {
			my $running = 1;
			$SIG{'TERM'} = sub { print STDERR "worker SIGTERM\n"; $running = 0; };

			setlocale(LC_ALL, $ENV{LC_ALL});
			radiusd::radlog(L_DBG, "oauth2 worker ($realm): started (tid=${\threads->tid()})");

			our ($authorization_var, $authorization_ttl);
			
			sub authorization {
				return $authorization_var if (defined($authorization_var) && $authorization_ttl > time());

				radiusd::radlog(L_DBG, "oauth2 worker ($realm): fetching token");

                my %params = (
                    client_id => $client_id,
                    scope     => "https://${graph_origin}/.default",
                    grant_type => 'client_credentials'
                );

                if ($client_key_path && -f $client_key_path) {
                    radiusd::radlog(L_DBG, "oauth2 worker ($realm): using certificate auth");
                    # 调用时传入 key 和 cert 路径
                    my $jwt = generate_client_assertion($client_id, $discovery->{token_endpoint}, $client_key_path, $client_cert_path);
                    if ($jwt) {
                        $params{client_assertion_type} = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
                        $params{client_assertion} = $jwt;
                    } else {
                        radiusd::radlog(L_ERR, "worker ($realm): failed to generate jwt");
                        return undef;
                    }
                } else {
                    $params{client_secret} = $client_secret;
                }

				my $r = $ua->post($discovery->{token_endpoint}, \%params);
				unless ($r->is_success) {
					radiusd::radlog(L_ERR, "oauth2 worker ($realm): token failed: ${\$r->status_line}");
                    if ($r->code == 400 || $r->code == 401) {
                        radiusd::radlog(L_ERR, "oauth2 worker ($realm): Azure said: " . $r->decoded_content);
                    }
					return undef;
				}

				my $token = decode_json $r->decoded_content;
				$authorization_var = "${\$token->{token_type}} ${\$token->{access_token}}";
				$authorization_ttl = time() + $token->{expires_in};
				return $authorization_var;
			}

			sub fetch {
				my ($purpose, $uri) = @_;
                
                my $auth_header = &authorization();
                unless (defined($auth_header)) {
                    radiusd::radlog(L_WARN, "oauth2 worker ($realm): Skipping $purpose sync because token is unavailable");
                    return undef;
                }

				my $r = $ua->get($uri, Authorization => $auth_header, Prefer => 'return=minimal', Accept => 'application/json');
				
                unless ($r->is_success) {
					if ($r->code == HTTP::Status::HTTP_UNAUTHORIZED) {
						$authorization_var = undef;
						return &fetch($purpose, $uri);
					} elsif ($r->code == HTTP::Status::HTTP_TOO_MANY_REQUESTS) {
						my $sleep = (int($r->header('Retry-After')) || 10) + 1;
						radiusd::radlog(L_WARN, "oauth2 worker ($realm): $purpose throttled, sleeping for $sleep seconds");
						sleep($sleep);
						return &fetch($purpose, $uri);
					}
					radiusd::radlog(L_WARN, "oauth2 worker ($realm): $purpose failed: ${\$r->status_line}");
					die "token ($realm): ${\$r->status_line}" if (is_server_error($r->code));
					return undef;
				}
				return decode_json $r->decoded_content;
			}

			sub walk {
				my ($purpose, $uri, $callback) = @_;
				my $delta;
				while (defined($uri)) {
					radiusd::radlog(L_DBG, "oauth2 worker ($realm): $purpose page");
					my $data = &fetch($purpose, $uri);
                    last unless defined($data);
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
				radiusd::radlog(L_INFO, "oauth2 worker ($realm): sync");

				radiusd::radlog(L_DBG, "oauth2 worker ($realm): sync users");
				$usersUri = &walk('users', $usersUri, sub {
					my ($data) = @_;
                    return unless defined($data);
					foreach my $d (grep { ($_->{isResourceAccount} || JSON::PP::false) != JSON::PP::true } @$data) {
						my $id = $d->{id};
						if (exists($d->{'@removed'}) && $d->{'@removed'}{reason} eq 'deleted') {
							delete $users{$id};
						} else {
							my $r = exists($users{$id}) ? $users{$id} : shared_clone({});
							$users{$id} = $r;
							$r->{R} = exists($d->{'@removed'});
							$r->{n} = $d->{userPrincipalName} if (exists($d->{userPrincipalName}));
							$r->{e} = $d->{accountEnabled} == JSON::PP::true if (exists($d->{accountEnabled}));
							$r->{p} = to_radtime($d->{lastPasswordChangeDateTime}) if (exists($d->{lastPasswordChangeDateTime}));
						}
					}
				});

				radiusd::radlog(L_DBG, "oauth2 worker ($realm): sync groups");
				$groupsUri = &walk('groups', $groupsUri, sub {
					my ($data) = @_;
                    return unless defined($data);
					foreach my $d (@$data) {
						my $id = $d->{id};
						if (exists($d->{'@removed'}) && $d->{'@removed'}{reason} eq 'deleted') {
							delete $groups{$id};
						} else {
							unless (exists($groups{$id})) {
								$groups{$id} = shared_clone({});
								$groups{$id}->{m} = shared_clone({});
							}
							my $r = $groups{$id};
							$r->{R} = exists($d->{'@removed'});
							$r->{n} = $d->{displayName} if (exists($d->{displayName}));
							foreach (@{$d->{'members@delta'}}) {
								if (exists($_->{'@removed'})) {
									delete $r->{m}->{$_->{id}};
								} else {
									$r->{m}->{$_->{id}} = undef;
								}
							}
						}
					}
				});

				radiusd::radlog(L_DBG, "oauth2 worker ($realm): apply");
				my %db :shared;
				$db{t} = $discovery->{token_endpoint};
				$db{u} = shared_clone({});
				$db{u}{lc $users{$_}->{n}} = $users{$_}->{p} foreach grep { !$users{$_}->{R} && $users{$_}->{e} } keys %users;
				$db{g} = shared_clone({});
				foreach (grep { !$groups{$_}->{R} } keys %groups) {
					my @m = map { lc $users{$_}->{n} } grep { $users{$_}->{e} } keys %{$groups{$_}->{m}};
					$db{g}->{$groups{$_}->{n}} = shared_clone({ map { $_, undef } @m }) if (scalar @m);
				}

				{
					lock(%{$realms{$realm}});
					%{$realms{$realm}} = %db;
					cond_signal(%{$realms{$realm}});
				}

				$pacing = 0;
				my $sleep = int($ttl - ($ttl / 3) + rand(2 * $ttl / 3));
				radiusd::radlog(L_INFO, "oauth2 worker ($realm): syncing in $sleep seconds");
				sleep($sleep);
			}
		};
		$thr->join();
		$thr = undef;
		last unless ($running);
		my $sleep = $pacing ** 2;
		radiusd::radlog(L_WARN, "oauth2 worker ($realm): died, sleeping for $sleep seconds");
		sleep($sleep);
		$pacing++ if ($pacing < 10);
	}
}

sub authorize {
	radiusd::radlog(L_DBG, 'oauth2 authorize');

	my $username = $RAD_REQUEST{'User-Name'};
	my $realm = $RAD_REQUEST{'Realm'};
	return RLM_MODULE_INVALID unless (defined($username) && defined($realm));

	{
		lock(%realms);
		unless (exists($realms{$realm})) {
			my $discovery_uri = radiusd::xlat(radiusd::xlat("%{config:realm[$realm].oauth2.discovery}"));
			my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
			my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
            my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");
            # 新增: 获取证书路径
            my $client_cert_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_cert_path}");
            
            # 容错: 如果没配 cert_path，但配了 key_path，尝试默认它们在同一个文件
            if ($client_key_path && (!$client_cert_path || $client_cert_path eq '')) {
                $client_cert_path = $client_key_path;
            }

			if ($client_id eq '' || ($client_secret eq '' && (!$client_key_path || ! -f $client_key_path))) {
                radiusd::radlog(L_ERR, "oauth2: missing client_id, or both client_secret and client_key_path are missing/invalid");
                return RLM_MODULE_FAIL;
            }

			$realms{$realm} = shared_clone({});
			lock(%{$realms{$realm}});
            # 传递 client_cert_path 给 worker
			push @sups, threads->create(\&worker, $realm, $discovery_uri, $client_id, $client_secret, $client_key_path, $client_cert_path);
			cond_wait(%{$realms{$realm}});
		}
	}

	my $state;
	{
		lock(%{$realms{$realm}});
		$state = $realms{$realm};
	}

	return RLM_MODULE_NOTFOUND unless (exists($state->{u}{lc $username}));

	$RAD_REQUEST{'OAuth2-Group'} = reduce { push @$a, $b if (exists($state->{g}{$b}{lc $username})); $a; } [], keys %{$state->{g}};
	$RAD_CHECK{'OAuth2-Password-Last-Modified'} = $state->{u}{lc $username};
	$RAD_CHECK{'Auth-Type'} = 'oauth2';

	return RLM_MODULE_UPDATED;
}

sub authenticate {
	radiusd::radlog(L_DBG, 'oauth2 authenticate');

	my $username = $RAD_REQUEST{'User-Name'};
	my $realm = $RAD_REQUEST{'Realm'};

	my $state;
	{
		lock(%{$realms{$realm}});
		$state = $realms{$realm};
	}
	my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
	my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
    my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");
    # 新增: 获取证书路径
    my $client_cert_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_cert_path}");
    
    # 容错逻辑同上
    if ($client_key_path && (!$client_cert_path || $client_cert_path eq '')) {
        $client_cert_path = $client_key_path;
    }

	radiusd::radlog(L_INFO, "oauth2 token auth for $username");

    my %params = (
		client_id => $client_id,
		scope => 'openid email',
		grant_type => 'password',
		username => $username,
		password => $RAD_REQUEST{'User-Password'}
    );

    if ($client_key_path && -f $client_key_path) {
        radiusd::radlog(L_DBG, "oauth2 authenticate: using certificate");
        # 传入 key 和 cert 路径
        my $jwt = generate_client_assertion($client_id, $state->{t}, $client_key_path, $client_cert_path);
        if ($jwt) {
            $params{client_assertion_type} = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
            $params{client_assertion} = $jwt;
        } else {
            return RLM_MODULE_FAIL;
        }
    } else {
        radiusd::radlog(L_DBG, "oauth2 authenticate: using secret");
        $params{client_secret} = $client_secret;
    }

	my $r = $ua->post($state->{t}, \%params);
	unless ($r->is_success) {
		radiusd::radlog(L_ERR, "oauth2 token failed: ${\$r->status_line}");
		return RLM_MODULE_FAIL if (is_server_error($r->code));
		my $response = decode_json $r->decoded_content;
		my @e = ( 'Error: ' . $response->{'error'} );
		push @e, split /\r\n/ms, $response->{'error_description'}
			if (defined($response->{'error_description'}));
		$RAD_REPLY{'Reply-Message'} = \@e;
		return RLM_MODULE_REJECT;
	}

	return RLM_MODULE_OK;
}

sub detach {
	radiusd::radlog(L_DBG, 'oauth2 detach');
}
