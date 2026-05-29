# crowdsec-lib.pl
# Common functions for CrowdSec Webmin module

BEGIN { push(@INC, ".."); };
use WebminCore;
&init_config();

# Check if cscli is executable on the system
sub check_crowdsec_binaries {
    my $cscli = $config{'cscli_path'} || '/usr/bin/cscli';
    return (-x $cscli) ? 1 : 0;
}

# Determine the service status.
# IMPORTANT: We call systemctl directly instead of going through Webmin's
# init module. init::status_service() can return a list in certain Webmin/init
# combinations, and that list survives as an ARRAY ref when interpolated into
# UI strings or URLs (the "ARRAY(0x...)" bug). Calling systemctl directly
# guarantees a clean scalar 0 or 1 is always returned.
sub get_crowdsec_status {
    my $service = $config{'crowdsec_service'} || 'crowdsec';
    my $out = &backquote_command("systemctl is-active " . quotemeta($service) . " 2>/dev/null");
    chomp($out);
    return ($out eq 'active') ? 1 : 0;
}

# Start, stop, or restart the service
sub control_crowdsec_service {
    my ($action) = @_;
    my $service = $config{'crowdsec_service'} || 'crowdsec';

    if ($action ne 'start' && $action ne 'stop' && $action ne 'restart') {
        return "Invalid service action: $action";
    }

    if (&foreign_check("init")) {
        &foreign_require("init", "init-lib.pl");
        my $rv;
        if ($action eq 'start') {
            $rv = &init::start_service($service);
        } elsif ($action eq 'stop') {
            $rv = &init::stop_service($service);
        } elsif ($action eq 'restart') {
            $rv = &init::restart_service($service);
        }
        # init service functions return undef or 0 on success, an error string
        # on failure. Some versions return a list; we only need the first element.
        $rv = ref($rv) eq 'ARRAY' ? $rv->[0] : $rv;
        return undef if (!defined($rv) || $rv eq '' || $rv eq '0' || $rv == 0);
        return "$rv";   # Force to plain string in case it's an object
    }

    # Fallback: direct systemctl
    my $cmd = "systemctl " . quotemeta($action) . " " . quotemeta($service) . " 2>&1";
    my $out = &backquote_logged($cmd);
    return $? == 0 ? undef : $out;
}

# Generic helper to execute cscli and parse JSON safely.
#
# KEY FIX: we redirect stderr to /dev/null (not to stdout).
# Using 2>&1 was mixing cscli warning/log lines into the JSON output, which
# caused JSON::PP to fail silently and return undef — leaving the decisions
# list empty or producing N/A values downstream.
sub run_cscli_json {
    my ($args) = @_;
    my $cscli = $config{'cscli_path'} || '/usr/bin/cscli';
    if (!-x $cscli) {
        return undef;
    }

    my $cmd = quotemeta($cscli) . " " . $args . " -o json 2>/dev/null";
    my $out = &backquote_command($cmd);

    if (!defined($out) || $out eq '') {
        return undef;
    }

    # Strip any leading/trailing whitespace that could trip up the JSON parser
    $out =~ s/^\s+|\s+$//g;

    my $decoded;
    eval {
        require JSON::PP;
        $decoded = JSON::PP::decode_json($out);
    };
    if ($@) {
        return undef;   # Degrade gracefully on parse error
    }
    return $decoded;
}

# Retrieve active decisions (banned IPs) and flatten the nested alert structure.
#
# KEY FIX: cscli decisions list -o json returns an array of *alert* objects.
# Each alert wraps one or more actual decision hashes inside its "decisions" key.
# Returning the raw alert array (the old behaviour) produced N/A for IP, Origin
# and Duration because alert objects carry those fields only on their nested
# decision children, not at the top level.
# This function extracts and enriches those child decision hashes.
sub get_decisions {
    my $res = &run_cscli_json("decisions list");
    my @flat_decisions = ();

    # Nothing came back (cscli unavailable or returned empty/null)
    return \@flat_decisions unless defined($res);

    if (ref($res) eq 'ARRAY') {
        foreach my $alert (@$res) {
            next unless ref($alert) eq 'HASH';

            if (ref($alert->{'decisions'}) eq 'ARRAY' && @{$alert->{'decisions'}} > 0) {
                # --- Modern cscli format ---
                # The alert wraps one or more decision objects. Extract each one
                # and backfill any fields that may be absent in older builds.
                foreach my $dec (@{$alert->{'decisions'}}) {
                    next unless ref($dec) eq 'HASH';

                    # 'scenario' lives on both the alert and the decision;
                    # prefer the decision's own value but fall back to the alert.
                    $dec->{'scenario'} ||= $alert->{'scenario'};

                    # 'origin' ("crowdsec", "cscli", "CAPI" …) is on the
                    # decision in modern builds; the alert's 'kind' field holds
                    # the same information in older builds.
                    $dec->{'origin'} ||= $alert->{'kind'};

                    # In some older cscli versions the banned IP was only in
                    # source.value on the parent alert, not in decision.value.
                    if (!defined($dec->{'value'}) || $dec->{'value'} eq '') {
                        if (ref($alert->{'source'}) eq 'HASH' &&
                            defined($alert->{'source'}{'value'})) {
                            $dec->{'value'} = $alert->{'source'}{'value'};
                        }
                    }

                    push(@flat_decisions, $dec);
                }

            } elsif (defined($alert->{'value'}) && defined($alert->{'type'})) {
                # --- Legacy flat format ---
                # Older cscli versions emitted a plain array of decision objects
                # without the alert wrapper; handle that here.
                push(@flat_decisions, $alert);
            }
            # Alerts with an empty decisions array (no active decision) are
            # intentionally skipped.
        }

    } elsif (ref($res) eq 'HASH') {
        # Some API responses wrap the list: {"decisions": [...]}
        if (ref($res->{'decisions'}) eq 'ARRAY') {
            foreach my $dec (@{$res->{'decisions'}}) {
                push(@flat_decisions, $dec) if ref($dec) eq 'HASH';
            }
        }
    }

    return \@flat_decisions;
}

# Retrieve bouncers list, always returning a guaranteed array ref
sub get_bouncers {
    my $res = &run_cscli_json("bouncers list");
    return (ref($res) eq 'ARRAY') ? $res : [];
}

# Get Hub parser and scenario counts
sub get_hub_status {
    my $parsers   = _normalize_hub_list(&run_cscli_json("parsers list"));
    my $scenarios = _normalize_hub_list(&run_cscli_json("scenarios list"));

    my $p_count = 0;
    foreach my $p (@$parsers) {
        next unless ref($p) eq 'HASH';
        $p_count++ if ($p->{'status'} eq 'enabled' || $p->{'installed'});
    }

    my $s_count = 0;
    foreach my $s (@$scenarios) {
        next unless ref($s) eq 'HASH';
        $s_count++ if ($s->{'status'} eq 'enabled' || $s->{'installed'});
    }

    return ($p_count, $s_count);
}

# Internal helper: coerce various hub-list response shapes into a plain array ref.
# Some cscli versions wrap results as {"parsers":[...]}, {"items":[...]}, etc.
sub _normalize_hub_list {
    my ($res) = @_;
    return []                if !defined($res);
    return $res              if ref($res) eq 'ARRAY';
    if (ref($res) eq 'HASH') {
        foreach my $key (qw(parsers scenarios collections postoverflows items)) {
            return $res->{$key} if ref($res->{$key}) eq 'ARRAY';
        }
    }
    return [];
}

# Delete a decision by numeric ID or by IP string (unban)
sub delete_decision {
    my ($id, $ip) = @_;
    my $cscli = $config{'cscli_path'} || '/usr/bin/cscli';
    my $cmd;
    if ($id && $id =~ /^\d+$/) {
        $cmd = quotemeta($cscli) . " decisions delete --id " . quotemeta($id) . " 2>&1";
    } elsif ($ip) {
        $cmd = quotemeta($cscli) . " decisions delete -i " . quotemeta($ip) . " 2>&1";
    } else {
        return "No valid ID or IP address provided for deletion";
    }
    my $out = &backquote_logged($cmd);
    return $? == 0 ? undef : $out;
}

# Manually add a ban decision
sub add_decision_ban {
    my ($ip, $duration, $reason) = @_;
    my $cscli = $config{'cscli_path'} || '/usr/bin/cscli';
    $duration ||= "4h";
    $reason   ||= "Manual ban from Webmin";
    my $cmd = quotemeta($cscli)
            . " decisions add -i " . quotemeta($ip)
            . " -d "               . quotemeta($duration)
            . " -r "               . quotemeta($reason)
            . " 2>&1";
    my $out = &backquote_logged($cmd);
    return $? == 0 ? undef : $out;
}

1;
