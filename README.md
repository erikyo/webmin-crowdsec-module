# CrowdSec Webmin Module

A lightweight and intuitive Webmin module to monitor and manage the CrowdSec security engine directly from your dashboard.

<img width="1448" height="733" alt="image" src="https://github.com/user-attachments/assets/38b9a57b-a816-4676-8235-8652fee67cd2" />

## Features

* **Service Control**: View current status and easily start, stop, or restart the CrowdSec daemon.
* **Metrics Summary**: Real-time counters for active parsers, active scenarios, and registered bouncers.
* **Active Decisions Management**: A clean overview of all currently banned IPs/ranges, showing the triggering scenario, origin, action type, and remaining ban duration.
* **Quick Unban**: Instantly remove active bans with a single click.
* **Manual Ban**: Ban any IP address or CIDR range manually, with custom duration (e.g., `4h`, `7d`) and specific reasons.

## Installation

Follow these steps to install the module in Webmin:

1. Download or package this repository as a `.tar.gz` or `.wbm` archive.
2. Log in to your **Webmin** dashboard with administrative privileges.
3. In the left-hand menu, navigate to **Webmin** -> **Webmin Configuration**.
4. Click on the **Webmin Modules** icon.
5. In the **Install module** section:
   * Select **From uploaded file** if you downloaded the archive locally, or **From local file** if it is already on the server.
   * Choose the module archive file.
6. Click the **Install Module** button.

## Configuration

If your system uses non-standard paths, you can adjust them in the module configuration:
* **Path to crowdsec executable**: (Default: `/usr/bin/crowdsec`)
* **Path to cscli executable**: (Default: `/usr/bin/cscli`)
* **CrowdSec systemd service name**: (Default: `crowdsec`)
