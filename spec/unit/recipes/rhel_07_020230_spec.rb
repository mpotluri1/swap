#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020230
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020230
#
# Rule ID: SV-86617r1_rule
#
# Vuln ID: V-71993
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The x86 Ctrl-Alt-Delete key sequence must be disabled. ###
# A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.

######
#
# Check:
#
# Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.# # Check that the ctrl-alt-del.service is not active with the following command:# # # systemctl status ctrl-alt-del.service# reboot.target - Reboot# Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)# Active: inactive (dead)# Docs: man:systemd.special(7)# # If the ctrl-alt-del.service is active, this is a finding.#
#
######
#
# Fix:
#
# Configure the system to disable the Ctrl-Alt_Delete sequence for the command line with the following command:# # # systemctl mask ctrl-alt-del.target# # If GNOME is active on the system, create a database to contain the system-wide setting (if it does not already exist) with the following command:# # # cat /etc/dconf/db/local.d/00-disable-CAD# # Add the setting to disable the Ctrl-Alt_Delete sequence for GNOME:# # [org/gnome/settings-daemon/plugins/media-keys]# logout=’’#
#
######

require 'spec_helper'

describe '::rhel_07_020230' do
  context 'When all attributes are default, on an Ubuntu 16.04' do
    let(:chef_run) do
      # for a complete list of available platforms and versions see:
      # https://github.com/customink/fauxhai/blob/master/PLATFORMS.md
      runner = ChefSpec::ServerRunner.new(platform: 'ubuntu', version: '16.04')
      runner.converge(described_recipe)
    end

    it 'converges successfully' do
      expect { chef_run }.to_not raise_error
    end
  end
end

######
#
# Overide guidance:
#
######
