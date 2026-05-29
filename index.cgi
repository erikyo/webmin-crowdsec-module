#!/usr/bin/perl
# index.cgi
# Main UI dashboard for the CrowdSec Webmin module

require './crowdsec-lib.pl';

&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);

# -----------------------------------------------------------------------
# 1. Validate cscli is present before attempting anything else
# -----------------------------------------------------------------------
if (!&check_crowdsec_binaries()) {
    print &ui_config_link($text{'index_cscli_missing'}, [ $config{'cscli_path'} ]);
    &ui_print_footer();
    exit;
}

# -----------------------------------------------------------------------
# 2. Service status + control buttons
#
# get_crowdsec_status() is guaranteed to return the integer 1 or 0 (see
# crowdsec-lib.pl).  We compare with == 1 to be explicit and avoid any
# accidental truthy/ARRAY confusion that plagued the previous version.
# -----------------------------------------------------------------------
my $running = &get_crowdsec_status();
my $is_running = ($running == 1) ? 1 : 0;

print &ui_subheading($text{'index_status'});

if ($is_running) {
    print "<p><span style='color:green; font-weight:bold;'>"
        . "<i class='fa fa-check-circle'></i> $text{'index_running'}"
        . "</span></p>\n";
} else {
    print "<p><span style='color:red; font-weight:bold;'>"
        . "<i class='fa fa-times-circle'></i> $text{'index_stopped'}"
        . "</span></p>\n";
}

# Pure HTML forms — no Webmin button helpers — to guarantee correct rendering
# across all themes and completely avoid theme-side array-stringification bugs.
print "<table class='table' style='width:100%; border:none; margin-bottom:25px;'>\n";

if ($is_running) {
    print "<tr>\n";
    print "  <td style='border:none; width:140px; padding:5px 0;'>\n";
    print "    <form action='action.cgi' method='post' style='margin:0;'>\n";
    print "    <input type='hidden' name='action' value='stop'>\n";
    print "    <input type='submit' value='$text{'index_stop'}' class='btn btn-danger'>\n";
    print "    </form>\n";
    print "  </td>\n";
    print "  <td style='border:none; vertical-align:middle; padding:5px;'>"
        . "Stop the CrowdSec protection engine daemon.</td>\n";
    print "</tr>\n";

    print "<tr>\n";
    print "  <td style='border:none; width:140px; padding:5px 0;'>\n";
    print "    <form action='action.cgi' method='post' style='margin:0;'>\n";
    print "    <input type='hidden' name='action' value='restart'>\n";
    print "    <input type='submit' value='$text{'index_restart'}' class='btn btn-warning'>\n";
    print "    </form>\n";
    print "  </td>\n";
    print "  <td style='border:none; vertical-align:middle; padding:5px;'>"
        . "Restart the CrowdSec protection engine daemon to apply config changes.</td>\n";
    print "</tr>\n";
} else {
    print "<tr>\n";
    print "  <td style='border:none; width:140px; padding:5px 0;'>\n";
    print "    <form action='action.cgi' method='post' style='margin:0;'>\n";
    print "    <input type='hidden' name='action' value='start'>\n";
    print "    <input type='submit' value='$text{'index_start'}' class='btn btn-success'>\n";
    print "    </form>\n";
    print "  </td>\n";
    print "  <td style='border:none; vertical-align:middle; padding:5px;'>"
        . "Start the CrowdSec protection engine daemon.</td>\n";
    print "</tr>\n";
}

print "</table>\n";

# -----------------------------------------------------------------------
# 3. Core component statistics
# -----------------------------------------------------------------------
my ($p_count, $s_count) = &get_hub_status();
my $bouncers = &get_bouncers();
my $b_count  = scalar(@$bouncers);

print &ui_subheading($text{'index_metrics'});
print "<table class='table table-striped table-bordered' style='width:100%; margin-bottom:20px;'>\n";
print "<thead><tr>";
print "<th>$text{'index_parsers'}</th>";
print "<th>$text{'index_scenarios'}</th>";
print "<th>$text{'index_bouncers'}</th>";
print "</tr></thead>\n";
print "<tbody><tr>";
print "<td>$p_count installed / enabled</td>";
print "<td>$s_count installed / enabled</td>";
print "<td>$b_count registered bouncer(s)</td>";
print "</tr></tbody></table>\n";

# -----------------------------------------------------------------------
# 4. Active decisions table
#
# KEY FIX: get_decisions() now returns properly flattened *decision* objects
# (not the raw alert wrappers).  The correct field mapping is:
#   $d->{'value'}    — banned IP / range
#   $d->{'origin'}   — who created the ban ("crowdsec", "cscli", "CAPI" …)
#   $d->{'duration'} — remaining ban time  ("3h44m45s", …)
#   $d->{'scenario'} — rule that triggered the ban
#   $d->{'type'}     — decision type ("ban", "captcha", …)
#   $d->{'id'}       — numeric decision ID used for targeted deletion
# -----------------------------------------------------------------------
print &ui_subheading($text{'index_decisions'});

my $decisions = &get_decisions();

if (!@$decisions) {
    print "<div class='alert alert-info'>$text{'index_no_decisions'}</div>\n";
} else {
    print "<table class='table table-striped table-hover table-condensed dataTable no-footer' style='width:100%; margin-bottom:20px;'>\n";
    print "<thead><tr>";
    print "<th>$text{'index_ip'}</th>";
    print "<th>$text{'index_reason'}</th>";
    print "<th>$text{'index_origin'}</th>";
    print "<th>$text{'index_action'}</th>";
    print "<th>$text{'index_duration'}</th>";
    print "<th>$text{'index_delete'}</th>";
    print "</tr></thead>\n<tbody>\n";

    foreach my $d (@$decisions) {
        # Extract fields — all three that were showing N/A now come from the
        # correctly-flattened decision object, not from the alert wrapper.
        my $id       = defined($d->{'id'})       ? $d->{'id'}       : '';
        my $ip       = defined($d->{'value'})    && $d->{'value'}    ne '' ? $d->{'value'}    : 'N/A';
        my $reason   = defined($d->{'scenario'}) && $d->{'scenario'} ne '' ? $d->{'scenario'} : 'N/A';
        my $origin   = defined($d->{'origin'})   && $d->{'origin'}   ne '' ? $d->{'origin'}   : 'N/A';
        my $action   = defined($d->{'type'})     && $d->{'type'}     ne '' ? $d->{'type'}     : 'ban';
        my $duration = defined($d->{'duration'}) && $d->{'duration'} ne '' ? $d->{'duration'} : 'N/A';

        # HTML-escape every value we render to prevent XSS from rogue IP strings
        my $ip_safe       = &html_escape($ip);
        my $reason_safe   = &html_escape($reason);
        my $origin_safe   = &html_escape($origin);
        my $action_safe   = &html_escape($action);
        my $duration_safe = &html_escape($duration);
        my $id_safe       = &html_escape($id);

        # Use URL-encoded values in the delete link
        my $ip_enc = &urlize($ip);
        my $del_url  = "action.cgi?action=delete&id=${id_safe}&ip=${ip_enc}";
        my $del_link = "<a href='${del_url}' class='btn btn-danger btn-xs' "
                     . "onclick='return confirm(\"Are you sure you want to unban ${ip_safe}?\");'>"
                     . "<i class='fa fa-trash'></i> $text{'index_delete'}</a>";

        print "<tr>";
        print "<td><b>${ip_safe}</b></td>";
        print "<td>${reason_safe}</td>";
        print "<td>${origin_safe}</td>";
        print "<td>${action_safe}</td>";
        print "<td>${duration_safe}</td>";
        print "<td>${del_link}</td>";
        print "</tr>\n";
    }

    print "</tbody></table>\n";
}

# -----------------------------------------------------------------------
# 5. Manual ban form
# -----------------------------------------------------------------------
print &ui_subheading($text{'index_add_decision'});
print "<form action='action.cgi' method='post'>\n";
print "<input type='hidden' name='action' value='add'>\n";
print &ui_table_start(undef, "width=100%", 2);
print &ui_table_row($text{'index_add_ip'},
    "<input type='text' name='ip' size='30' class='form-control' "
    . "placeholder='e.g. 1.2.3.4 or 1.2.3.0/24'>");
print &ui_table_row($text{'index_add_duration'},
    "<input type='text' name='duration' value='4h' size='10' class='form-control'>");
print &ui_table_row($text{'index_add_reason'},
    "<input type='text' name='reason' value='Manual ban via Webmin' size='50' class='form-control'>");
print &ui_table_end();
print "<div style='margin-top:10px;'>";
print "<input type='submit' value='$text{'index_add_submit'}' class='btn btn-primary'>";
print "</div>\n";
print "</form>\n";

&ui_print_footer("/", "Return to main menu");
