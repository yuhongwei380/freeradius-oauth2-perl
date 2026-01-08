use strict;
use warnings;
use threads;
use threads::shared;
use LWP::UserAgent;
use JSON::PP;
use Time::Piece;
use File::Slurp;
use Crypt::JWT qw(encode_jwt);

# 共享变量，用于存储各个 Realm 的 Access Token
my %tokens :shared;

# 日志级别常量
use constant {
    L_DBG  => 1,
    L_AUTH => 2,
    L_INFO => 3,
    L_ERR  => 4,
};

# --- 模块初始化 ---
sub instantiate {
    radiusd::radlog(L_INFO, "rlm_perl: oauth2 module initializing...");
    return 0;
}

# --- 核心认证函数 ---
sub authorize {
    my $username = $RAD_REQUEST{'User-Name'};
    my $password = $RAD_REQUEST{'User-Password'};
    my $realm    = $RAD_REQUEST{'Realm'};

    # 获取配置
    my $discovery       = radiusd::xlat("%{config:realm[$realm].oauth2.discovery}");
    my $client_id       = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
    my $client_secret   = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
    my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");

    # 基础校验
    if (!$discovery || !$client_id) {
        radiusd::radlog(L_ERR, "oauth2 ($realm): Missing discovery or client_id in proxy.conf");
        return RLM_MODULE_FAIL;
    }

    # 如果该 Realm 的后台线程还没启动，则启动它
    if (!exists $tokens{$realm}) {
        {
            lock(%tokens);
            if (!exists $tokens{$realm}) {
                $tokens{$realm} = ''; # 占位
                threads->create(\&worker, $realm, $discovery, $client_id, $client_secret, $client_key_path)->detach();
                radiusd::radlog(L_INFO, "oauth2 ($realm): Background worker started");
            }
        }
    }

    # 等待 Token（最多等 3 秒，防止阻塞）
    my $retry = 30;
    while ($tokens{$realm} eq '' && $retry--) {
        select(undef, undef, undef, 0.1);
    }

    my $token = $tokens{$realm};
    if (!$token || $token eq 'ERROR') {
        radiusd::radlog(L_ERR, "oauth2 ($realm): No valid access token available");
        return RLM_MODULE_FAIL;
    }

    # 使用 Token 验证用户
    return verify_user($realm, $token, $username, $password);
}

# --- 后台刷新 Token 线程 ---
sub worker {
    my ($realm, $discovery, $client_id, $client_secret, $client_key_path) = @_;
    my $ua = LWP::UserAgent->new(timeout => 10);
    my $json = JSON::PP->new;

    radiusd::radlog(L_INFO, "oauth2 worker ($realm): Initializing with client_id=$client_id");

    while (1) {
        my $expires_in = 300; # 默认 5 分钟后重试
        
        eval {
            # 1. 获取 OpenID Discovery 配置
            my $res = $ua->get($discovery);
            die "Discovery failed: " . $res->status_line unless $res->is_success;
            my $conf = $json->decode($res->decoded_content);
            my $token_endpoint = $conf->{token_endpoint};

            # 2. 准备请求参数
            my %params = (
                grant_type => 'client_credentials',
                client_id  => $client_id,
                scope      => 'https://graph.microsoft.com/.default',
            );

            # 3. 身份验证：优先使用证书 (Private Key JWT)
            if ($client_key_path && -f $client_key_path) {
                radiusd::radlog(L_DBG, "oauth2 worker ($realm): Using Private Key JWT for auth");
                my $private_key_content = read_file($client_key_path);
                
                my $now = time();
                my $payload = {
                    aud => $token_endpoint,
                    exp => $now + 3600,
                    iss => $client_id,
                    sub => $client_id,
                    jti => "id" . $now . int(rand(10000)),
                    nbf => $now,
                    iat => $now,
                };

                # 生成 client_assertion
                my $assertion = encode_jwt(
                    payload => $payload, 
                    key => \$private_key_content, 
                    alg => 'RS256'
                );
                $params{client_assertion_type} = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
                $params{client_assertion}      = $assertion;
            } else {
                radiusd::radlog(L_DBG, "oauth2 worker ($realm): Using Client Secret for auth");
                $params{client_secret} = $client_secret;
            }

            # 4. 请求 Token
            my $token_res = $ua->post($token_endpoint, Content => \%params);
            if ($token_res->is_success) {
                my $data = $json->decode($token_res->decoded_content);
                {
                    lock(%tokens);
                    $tokens{$realm} = $data->{access_token};
                }
                $expires_in = ($data->{expires_in} || 3600) - 60;
                radiusd::radlog(L_INFO, "oauth2 worker ($realm): Token refreshed, next in $expires_in s");
            } else {
                die "Token request failed: " . $token_res->decoded_content;
            }
        };

        if ($@) {
            radiusd::radlog(L_ERR, "oauth2 worker ($realm) FATAL: $@");
            { lock(%tokens); $tokens{$realm} = 'ERROR'; }
            $expires_in = 60; # 出错后 1 分钟重试
        }

        sleep($expires_in > 0 ? $expires_in : 60);
    }
}

# --- 验证用户密码 (ROPC 流程) ---
sub verify_user {
    my ($realm, $token, $username, $password) = @_;
    my $ua = LWP::UserAgent->new(timeout => 5);
    my $json = JSON::PP->new;

    # 注意：Azure ROPC 验证通常需要 tenant ID 对应的 token endpoint
    # 这里我们使用通用的组织或特定的 discovery 中拿到的 endpoint
    my $res = $ua->post("https://login.microsoftonline.com/$realm/oauth2/v2.0/token", [
        grant_type => 'password',
        client_id  => radiusd::xlat("%{config:realm[$realm].oauth2.client_id}"),
        scope      => 'openid profile',
        username   => $username,
        password   => $password,
    ]);

    if ($res->is_success) {
        radiusd::radlog(L_AUTH, "oauth2 ($realm): User $username authenticated successfully");
        return RLM_MODULE_OK;
    } else {
        my $err_content = $res->decoded_content;
        radiusd::radlog(L_AUTH, "oauth2 ($realm): Auth failed for $username: $err_content");
        return RLM_MODULE_REJECT;
    }
}

sub detach { return RLM_MODULE_OK; }
1;
