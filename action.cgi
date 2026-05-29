#!/usr/bin/perl
# action.cgi
# Handler script for all CrowdSec module actions

require './crowdsec-lib.pl';

&ReadParse();
&error_setup($text{'err_action'});

my $action = $in{'action'};

# -----------------------------------------------------------------------
# Service control: start / stop / restart
# -----------------------------------------------------------------------
if ($action eq 'start' || $action eq 'stop' || $action eq 'restart') {
    my $err = &control_crowdsec_service($action);
    if ($err) {
        # control_crowdsec_service() always returns a plain string on error
        # (never an array ref), so this is safe to interpolate directly.
        &error("Failed to $action CrowdSec service: $err");
    }
    &webmin_log($action, "service");
}

# -----------------------------------------------------------------------
# Delete a decision (unban an IP)
# -----------------------------------------------------------------------
elsif ($action eq 'delete') {
    my $id = $in{'id'};
    my $ip = $in{'ip'};

    # Sanitise inputs — reject anything that isn't a plain integer or IP/CIDR
    if ($id && $id !~ /^\d+$/) {
        &error("Invalid decision ID: " . &html_escape($id));
    }
    if ($ip && $ip !~ m{^[\d\.\:/a-fA-F]+$}) {
        &error("Invalid IP address or range: " . &html_escape($ip));
    }
    if (!$id && !$ip) {
        &error("A decision ID or IP address is required to delete a ban.");
    }

    my $err = &delete_decision($id, $ip);
    if ($err) {
        &error("$text{'index_err_del'}: $err");
    }
    &webmin_log("delete", "decision", $ip || $id);
}

# -----------------------------------------------------------------------
# Add a manual ban
# -----------------------------------------------------------------------
elsif ($action eq 'add') {
    my $ip       = $in{'ip'};
    my $duration = $in{'duration'} || '4h';
    my $reason   = $in{'reason'}   || 'Manual ban via Webmin';

    if (!$ip) {
        &error("An IP address or CIDR range is required to add a ban.");
    }

    # Basic IP/CIDR sanity check
    if ($ip !~ m{^[\d\.\:/a-fA-F]+$}) {
        &error("Invalid IP address or range: " . &html_escape($ip));
    }

    # Sanity-check the duration format (e.g. 4h, 24h, 7d, 30m)
    if ($duration !~ /^\d+[smhd]$/) {
        &error("Invalid duration format '$duration'. Use values like 4h, 24h, 7d, 30m.");
    }

    my $err = &add_decision_ban($ip, $duration, $reason);
    if ($err) {
        &error("$text{'index_err_add'}: $err");
    }
    &webmin_log("add", "decision", $ip);
}

# -----------------------------------------------------------------------
# Unknown action
# -----------------------------------------------------------------------
else {
    &error("Unknown action: " . &html_escape($action));
}

# Redirect back to the dashboard on success
&redirect("index.cgi");
