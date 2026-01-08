use strict;
use warnings;
use LWP::UserAgent;
use JSON::PP;
use Time::Piece;
use File::Slurp;
use Crypt::JWT qw(encode_jwt);

# 日志级别常量
use constant {
    L_DBG  => 1,
    L_AUTH => 2,
    L_INFO => 3,
    L_ERR  => 4,
};

sub instantiate {
    radiusd::radlog(L_INFO, "rlm_perl: oauth2 (Certificate/ROPC) module initialized");
    return 0;
}

sub authorize {
    # 1. 获取请求信息
    my $username = $RAD_REQUEST{'User-Name'};
    my $password = $RAD_REQUEST{'User-Password'};
    my $realm    = $RAD_REQUEST{'Realm'};

    # 2. 获取配置
    # 确保 proxy.conf 中配置了 client_id 和 client_key_path
    my $client_id       = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
    my $client_key_path = radiusd::xlat("%{config:realm[$realm].oauth2.client_key_path}");
    
    # 获取 Token Endpoint (这里硬编码了通用格式，也可以从 discovery 获取)
    my $token_endpoint = "https://login.microsoftonline.com/$realm/oauth2/v2.0/token";

    if (!$username || !$password) {
        radiusd::radlog(L_ERR, "oauth2: Missing username or password");
        return RLM_MODULE_REJECT;
    }

    if (!$client_id || !$client_key_path) {
        radiusd::radlog(L_ERR, "oauth2: Missing client_id or client_key_path for realm $realm");
        return RLM_MODULE_FAIL;
    }

    if (! -f $client_key_path) {
        radiusd::radlog(L_ERR, "oauth2: Certificate key file not found: $client_key_path");
        return RLM_MODULE_FAIL;
    }

    radiusd::radlog(L_DBG, "oauth2: Preparing certificate auth for client $client_id");

    # 3. 生成 Client Assertion (Private Key JWT)
    # 这是你原本 worker 里的逻辑，现在移到主流程，用于 ROPC
    my $client_assertion = "";
    eval {
        my $private_key_content = read_file($client_key_path);
        my $now = time();
        my $payload = {
            aud => $token_endpoint, # Audience 必须匹配 Azure 的 Token URL
            exp => $now + 300,      # 5分钟有效期足够了
            iss => $client_id,
            sub => $client_id,
            jti => "id" . $now . int(rand(10000)),
            nbf => $now,
            iat => $now,
        };

        $client_assertion = encode_jwt(
            payload => $payload, 
            key     => \$private_key_content, 
            alg     => 'RS256'
        );
    };

    if ($@ || !$client_assertion) {
        radiusd::radlog(L_ERR, "oauth2: Failed to generate JWT assertion: $@");
        return RLM_MODULE_FAIL;
    }

    # 4. 发送 ROPC 请求 (带证书签名)
    my $ua = LWP::UserAgent->new(timeout => 5);
    
    my %post_data = (
        grant_type            => 'password',
        client_id             => $client_id,
        scope                 => 'openid profile', # ROPC 需要的 Scope
        username              => $username,
        password              => $password,
        # 关键修改：使用 JWT 进行客户端认证，代替 client_secret
        client_assertion_type => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion      => $client_assertion,
    );

    radiusd::radlog(L_DBG, "oauth2: Sending auth request to Azure AD for $username");

    my $res = $ua->post($token_endpoint, \%post_data);

    if ($res->is_success) {
        radiusd::radlog(L_AUTH, "oauth2: Login success for $username");
        return RLM_MODULE_OK;
    } else {
        my $error_msg = $res->decoded_content;
        # 尝试提取易读错误
        if ($error_msg =~ /"error_description":"(.*?)"/) {
            $error_msg = $1;
        }
        radiusd::radlog(L_AUTH, "oauth2: Login failed for $username. Azure says: $error_msg");
        return RLM_MODULE_REJECT;
    }
}

sub detach { return 0; }

1;
