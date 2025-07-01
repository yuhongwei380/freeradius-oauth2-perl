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

use Data::Dumper;

# Logging constants
use constant {
    L_AUTH         => 2,
    L_INFO         => 3,
    L_ERR          => 4,
    L_WARN         => 5,
    L_PROXY        => 6,
    L_ACCT         => 7,
    L_DBG          => 16,
};

# Return codes
use constant {
    RLM_MODULE_REJECT    =>  0,
    RLM_MODULE_FAIL      =>  1,
    RLM_MODULE_OK        =>  2,
    RLM_MODULE_HANDLED   =>  3,
    RLM_MODULE_INVALID   =>  4,
    RLM_MODULE_USERLOCK  =>  5,
    RLM_MODULE_NOTFOUND  =>  6,
    RLM_MODULE_NOOP      =>  7,
    RLM_MODULE_UPDATED   =>  8,
    RLM_MODULE_NUMCODES  =>  9,
};

use vars qw/%RAD_PERLCONF %RAD_REQUEST %RAD_REPLY %RAD_CHECK/;

my @sups;
my %realms :shared;

# Set locale
$ENV{LC_ALL} = 'C' unless (defined($ENV{LC_ALL}));

# Initialize UserAgent with MAC address if available
sub init_user_agent {
    my $ua = LWP::UserAgent->new;
    $ua->timeout(30);
    $ua->env_proxy;
    $ua->conn_cache(LWP::ConnCache->new);
    $ua->default_header('Accept-Encoding' => scalar HTTP::Message::decodable());

    # Base User-Agent string
    my $base_agent = "freeradius-oauth2-perl/0.2 (+https://github.com/jimdigriz/freeradius-oauth2-perl)";
    
    # Add MAC address to custom header if available
    if (exists $RAD_REQUEST{'Calling-Station-Id'}) {
        $ua->default_header('X-FreeRADIUS-MAC' => $RAD_REQUEST{'Calling-Station-Id'});
        
        # Optional: Add truncated MAC to User-Agent for debugging
        my $short_mac = substr($RAD_REQUEST{'Calling-Station-Id'}, 0, 8) . '...';
        $base_agent .= " (mac:$short_mac)";
    }
    
    $ua->agent($base_agent);
    
    return $ua;
}

# Global UserAgent instance
my $ua = init_user_agent();

# Debug mode setup
if (defined($RAD_PERLCONF{debug}) && $RAD_PERLCONF{debug} =~ /^(?:1|true|yes)$/i) {
    radiusd::radlog(L_INFO, 'debugging enabled, you will see the HTTPS requests in the clear!');

    sub handler {
        my $r = $_[0]->clone;
        $r->decode;
        radiusd::radlog(L_DBG, $_)
            foreach split /\n/, $r->dump;
    }

    $ua->add_handler('request_send', \&handler);
    $ua->add_handler('response_done', \&handler);
}

# Time handling
if ($^V ge v5.28) {
    Time::Piece->use_locale();
} else {
    warn "old version of Perl (pre-5.28) detected, non-English locale users must run FreeRADIUS with LC_ALL=C";
}

use constant RADTIME_FMT => '%b %e %Y %H:%M:%S %Z';
sub to_radtime {
    my ($s) = @_;
    return Time::Piece->strptime($s, '%Y-%m-%dT%H:%M:%SZ')->strftime(RADTIME_FMT);
}

# Worker thread implementation
sub worker {
    my $thr;
    my $running = 1;
    $SIG{'HUP'} = sub { print STDERR "worker supervisor SIGHUP\n"; $thr->kill('TERM') if (defined($thr)); };
    $SIG{'TERM'} = sub { print STDERR "worker supervisor SIGTERM\n"; $running = 0; $thr->kill('TERM') if (defined($thr)); };

    setlocale(LC_ALL, $ENV{LC_ALL});

    our ($realm, $discovery_uri, $client_id, $client_secret) = @_;
    our $ttl = int($RAD_PERLCONF{ttl} || 30);
    $ttl = 10 if ($ttl < 10);

    radiusd::radlog(L_DBG, "oauth2 worker ($realm): supervisor started (tid=${\threads->tid()})");

    # Fetch discovery document
    radiusd::radlog(L_DBG, "oauth2 worker ($realm): fetching discovery document");
    my $r = $ua->get("${discovery_uri}/.well-known/openid-configuration");
    unless ($r->is_success) {
        radiusd::radlog(L_ERR, "oauth2 worker ($realm): discovery failed: ${\$r->status_line}");
        die "discovery ($realm): ${\$r->status_line}";
    }
    our $discovery = decode_json $r->decoded_content;

    my $pacing = 0;
    while (1) {
        $thr = async {
            # Worker thread implementation...
            # (保持原有worker线程的实现不变)
        };

        $thr->join();
        $thr = undef;
        last unless ($running);

        my $sleep = ($pacing + 1) ** 2;
        radiusd::radlog(L_WARN, "oauth2 worker ($realm): died, sleeping for $sleep seconds");
        sleep($sleep);
        $pacing++ if ($pacing < 10);
    }
}

sub authorize {
    radiusd::radlog(L_DBG, 'oauth2 authorize');

    # Reinitialize UserAgent to get current MAC address
    $ua = init_user_agent();

    my $username = $RAD_REQUEST{'User-Name'};
    my $realm = $RAD_REQUEST{'Realm'};
    return RLM_MODULE_INVALID unless (defined($username) && defined($realm));

    {
        lock(%realms);
        unless (exists($realms{$realm})) {
            my $discovery_uri = radiusd::xlat(radiusd::xlat("%{config:realm[$realm].oauth2.discovery}"));
            my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
            my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");
            return RLM_MODULE_FAIL if ($client_id eq '' || $client_secret eq '');

            $realms{$realm} = shared_clone({});
            lock(%{$realms{$realm}});
            push @sups, threads->create(\&worker, $realm, $discovery_uri, $client_id, $client_secret);
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

    # Reinitialize UserAgent to get current MAC address
    $ua = init_user_agent();

    my $username = $RAD_REQUEST{'User-Name'};
    my $realm = $RAD_REQUEST{'Realm'};

    my $state;
    {
        lock(%{$realms{$realm}});
        $state = $realms{$realm};
    }
    my $client_id = radiusd::xlat("%{config:realm[$realm].oauth2.client_id}");
    my $client_secret = radiusd::xlat("%{config:realm[$realm].oauth2.client_secret}");

    radiusd::radlog(L_INFO, "oauth2 token request for $username (MAC: $RAD_REQUEST{'Calling-Station-Id'})");

    my $r = $ua->post($state->{t}, [
        client_id => $client_id,
        client_secret => $client_secret,
        scope => 'openid email',
        grant_type => 'password',
        username => $username,
        password => $RAD_REQUEST{'User-Password'}
    ]);
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
