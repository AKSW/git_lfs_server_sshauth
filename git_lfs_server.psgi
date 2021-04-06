#! perl
use strict;
use warnings;
use experimental 'signatures';
use Plack::Request;
use Plack::Builder;
use Plack::Util;
use Crypt::PK::ECC;
use Crypt::JWT qw(encode_jwt decode_jwt);
use Digest::SHA;
use Scope::Guard 'guard';
use Try::Tiny;
use JSON::PP;
use File::Path qw(make_path);
use Scalar::Util 'refaddr';
use IO::File;

my $key_file = "/opt/git_lfs_auth/secrets/key.der";

my $storage_path = '/data/lfs_storage/test';

my $jwt_enc = 'A128CBC-HS256';
my $jwt_alg = 'ECDH-ES+A128KW';

my $token_duration = 10 * 60;
my $upload_token_duration = 6 * 60 * 60;

sub load_key {
    return Crypt::PK::ECC->new($key_file);
}

my $jwt_pk = load_key();

sub jwt_enc ($payload, $duration = undef) {
    $duration = $token_duration unless defined $duration;
    return encode_jwt(
	key => $jwt_pk,
	payload => $payload,
	alg => $jwt_alg,
	enc => $jwt_enc,
	auto_iat => 1,
	relative_exp => $token_duration
       );
}

sub jwt_dec ($token) {
    return decode_jwt(
	key => $jwt_pk,
	token => $token,
	accepted_alg => $jwt_alg,
	accepted_enc => $jwt_enc
       );
}

sub auth_header ($token) {
    #return (Authorization => "Bearer $token");
    return (Token => $token);
}

sub json_response ($data) {
    ([ 'Content-Type' => 'application/json', ], [ encode_json $data ])
}

sub not_found {
    [ 404, [ 'Content-Type' => 'text/plain', ], [ 'not found' ] ]
}

sub client_failure ($msg) {
    [ 400, [ 'Content-Type' => 'text/plain', ], [ $msg ] ];
}

sub invalid_data {
    return client_failure('invalid data');
}

sub invalid_data_semantic {
    [ 422, [ 'Content-Type' => 'text/plain', ], [ 'invalid data' ] ]
}

sub forbidden {
    [ 403, [ 'Content-Type' => 'text/plain', ], [ 'forbidden' ] ]
}

sub storage_error {
    [ 507, [ 'Content-Type' => 'text/plain', ], [ 'storage error' ] ]
}

sub auth_token_from_env ($env) {
    if (exists $env->{HTTP_AUTHORIZATION} && $env->{HTTP_AUTHORIZATION} =~ /^bearer (.*)$/i) {
	return $1;
    }
    return undef;
}

sub make_href ($req, $project, @rest) {
    join "/", $req->base, $project, @rest
}

sub make_file_rdonly ($path) {
    my $f = IO::File->new($path, '<:raw');
    Plack::Util::set_io_path($f, $path) if defined $f;
    $f
}

my $app = sub {
    my $env = shift;
    my $req = Plack::Request->new($env);
    my $success;

    my $path = $req->path;
    my $time = time;

    if ($path eq '/token_factory') {
	my $user = $req->parameters->{user};
	my $project = $req->parameters->{project};
	my $domain = $req->user;
	return not_found unless defined $project;
	my $script_path = $req->script_name || '/';
	$project = "/$project" =~ s{^\Q$script_path/}{}r;

	unless (length $user and length $domain and length $project) {
	    return not_found;
	}
	$project =~ s/\.git$//;
	return not_found unless $project =~ m{^[^/]+/[^/]+$};
	return not_found if $project =~ /\0/ || $project =~ /\.\./;
	my $payload = +{
	    sub => $user,
	    aud => $project,
	};
	my $token = jwt_enc($payload);
	my $response = +{
	    href => make_href($req, $project),
	    header => { auth_header($token) },
	    expires_in => $token_duration - 1,
	};

	return [ 200, json_response($response) ];
    }

    if ($path =~ m{^/[^/]+/[^/]+/locks/verify$}) {
	return not_found;
    }

    my $token_data;
    for my $ah ($req->header('Token'), auth_token_from_env($env)) {
	next unless $ah;
	$success = try { $token_data = jwt_dec($ah); 1; };
	return forbidden unless $success;
    }

    my $args = $path;
    return not_found unless $args =~ s{^/(?<project>[^/]+/[^/]+)/}{};
    my $project = $+{project};
    return not_found if $project =~ /\0/ || $project =~ /\.\./;

    if ($args eq 'objects/batch') {
	my $data;
	$success = try { $data = decode_json $req->content; 1; };
	return invalid_data unless $success;
	return invalid_data_semantic unless $data->{operation};
	if (lc $data->{operation} eq 'download') {
	    return invalid_data_semantic unless ref $data->{objects} eq 'ARRAY';
	    my @objects;
	    for my $o (@{ $data->{objects} }) {
		next unless ref $o eq 'HASH';
		next unless defined $o->{oid};
		return invalid_data_semantic
		    unless $o->{oid} =~ /^((\w{2})(\w{2})(\w+))$/;
		my ($oid, $p1, $p2) = ($1, $2, $3);
		my $path = "$storage_path/store/$project/$p1/$p2/$oid";
		my $result;
		if (-e $path) {
		    $result = +{
			oid => $oid,
			size => -s $path,
			authenticated => \1,
			actions => {
			    download => {
				href => make_href($req, $project, 'ref', $oid),
			    },
			},
		    };
		}
		else {
		    $result = +{
			oid => $oid,
			error => {
			    code => 404,
			    message => 'not found',
			},
		    };
		}
		push @objects, $result;
	    }
	    return [ 200, json_response(+{
		objects => \@objects,
	    }) ];
	}
	elsif (lc $data->{operation} eq 'upload') {
	    return forbidden unless $token_data;
	    return forbidden unless defined $token_data->{aud};
	    return forbidden unless $token_data->{aud} eq $project;
	    return invalid_data_semantic unless ref $data->{objects} eq 'ARRAY';
	    my @objects;
	    for my $o (@{ $data->{objects} }) {
		next unless ref $o eq 'HASH';
		next unless defined $o->{oid};
		return invalid_data_semantic
		    unless $o->{oid} =~ /^((\w{2})(\w{2})(\w+))$/;
		my ($oid, $p1, $p2) = ($1, $2, $3);
		my $grant = +{
		    sub => $token_data->{sub},
		    aud => $project,
		    iss => 'store',
		};
		my $token = jwt_enc($grant, $upload_token_duration);

		my $path = "$storage_path/store/$project/$p1/$p2/$oid";
		my $result;
		if (-e $path) {
		    $result = +{
			oid => $oid,
			size => -s $path,
			authenticated => \1,
		    };
		}
		else {
		    $result = +{
			oid => $oid,
			size => ~~$o->{size},
			authenticated => \1,
			actions => {
			    upload => {
				href => make_href($req, $project, 'store', $oid),
				header => { auth_header($token) },
				expires_in => $upload_token_duration - 1,
			    },
			    verify => {
				href => make_href($req, $project, 'verify'),
				header => { auth_header($token) },
				expires_in => $upload_token_duration - 1,
			    },
			},
		    };
		}
		push @objects, $result;
	    }
	    return [ 200, json_response(+{
		objects => \@objects,
	    }) ];
	}
	return invalid_data_semantic;
    }
    elsif ($args eq 'verify') {
	return forbidden unless $token_data;
	return forbidden unless defined $token_data->{aud} && defined $token_data->{iss};
	return forbidden unless $token_data->{aud} eq $project && $token_data->{iss} eq 'store';
	my $o;
	$success = try { $o = decode_json $req->content; 1; };
	return invalid_data unless $success;
	return invalid_data_semantic unless defined $o->{oid};
	return invalid_data_semantic unless $o->{oid} =~ /^((\w{2})(\w{2})(\w+))$/;
	my ($oid, $p1, $p2) = ($1, $2, $3);
	my $path = "$storage_path/store/$project/$p1/$p2/$oid";
	if (-e $path && -s $path == ~~$o->{size}) {
	    return [ 200, [], [] ];
	} else {
	    return not_found;
	}
    }
    elsif ($args =~ m{^store/(?<oid>\w{5,})$}) {
	my $p_oid = $+{oid};
	my $id = {};
	return forbidden unless $token_data;
	return forbidden unless defined $token_data->{aud} && defined $token_data->{iss};
	return forbidden unless $token_data->{aud} eq $project && $token_data->{iss} eq 'store';
	return invalid_data_semantic unless $p_oid =~ /^((\w{2})(\w{2})(\w+))$/;
	my ($oid, $p1, $p2) = ($1, $2, $3);
	my $temp_base = "$storage_path/upload/$project/$p1/$p2";
	my $temp_path = join '.', "$temp_base/$oid", refaddr($id);
	$success = try { make_path($temp_base); 1; };
	return storage_error unless $success;
	my $cksum = Digest::SHA->new("SHA-256");
	my $total = 0;
	{
	    open my $out, '>:raw', $temp_path
		or return storage_error;
	    my $close = guard { close $out; };
	    my $input = '';
	    for (;;) {
		my $count = $req->input->read($input, 32_768);
		unless (defined $count) {
		    return [ 408, [ 'Content-Type' => 'text/plain' ],
			     [ "$!" ] ];
		}
		$total += $count;
		unless ($count) {
		    last;
		}
		$out->print($input)
		    or return storage_error;
		$cksum->add($input);
		$input = '';
	    }
	}
	return invalid_data
	    unless $cksum->hexdigest eq $oid;
	my $base = "$storage_path/store/$project/$p1/$p2";
	my $path = "$base/$oid";
	$success = try { make_path($base); 1; };
	return storage_error unless $success;
	rename $temp_path, $path
	    or return storage_error;
	if (open my $meta, '>', "$path.meta") {
	    my $close = guard { close $meta };
	    $meta->print("Upload-User: $token_data->{sub}\nSize: $total\n");
	}
	while ($temp_base =~ m{/} && rmdir $temp_base) {
	    $temp_base =~ s{/[^/]+$}{};
	}
	$! = 0;
	return [ 200, [], [] ];
    }
    elsif ($args =~ m{^ref/(?<oid>\w{5,})$}) {
	my $p_oid = $+{oid};
	return invalid_data_semantic unless $p_oid =~ /^((\w{2})(\w{2})(\w+))$/;
	my ($oid, $p1, $p2) = ($1, $2, $3);
	my $path = "$storage_path/store/$project/$p1/$p2/$oid";
	if (-e $path) {
	    return [ 200, [ 'Content-Type' => 'application/octet-stream' ], make_file_rdonly($path) ];
	} else {
	    return not_found;
	}
    }

    return not_found;
};

builder {
    enable sub ($app) {
	sub ($env) {
	    $env->{HTTPS} = 'ON'
		if $env->{'HTTP_X_FORWARDED_PROTO'} && $env->{'HTTP_X_FORWARDED_PROTO'} eq 'https';
	    $env->{'psgi.url_scheme'}  = 'https' if $env->{HTTPS} && uc $env->{HTTPS} eq 'ON';

	    return $app->($env);
	}
    };
    enable 'ConditionalGET';
    enable 'ETag';
    $app;
};
