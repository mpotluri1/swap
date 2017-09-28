#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021100
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021100
#
# Rule ID: SV-86675r1_rule
#
# Vuln ID: V-72051
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Cron logging must be implemented. ###
# Cron logging can be used to trace the successful or unsuccessful execution of cron jobs. It can also be used to spot intrusions into the use of the cron facility by unauthorized and malicious users.

######
#
# Check:
#
# Verify that "rsyslog" is configured to log cron events.# # Check the configuration of "/etc/rsyslog.conf" for the cron facility with the following command:# # Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf".# # # grep cron /etc/rsyslog.conf# cron.* /var/log/cron.log# # If the command does not return a response, check for cron logging all facilities by inspecting the "/etc/rsyslog.conf" file:# # # more /etc/rsyslog.conf# # Look for the following entry:# # *.* /var/log/messages# # If "rsyslog" is not logging messages for the cron facility or all facilities, this is a finding.# # If the entry is in the "/etc/rsyslog.conf" file but is after the entry "*.*", this is a finding.#
#
######
#
# Fix:
#
# Configure "rsyslog" to log all cron messages by adding or updating the following line to "/etc/rsyslog.conf":# # cron.* /var/log/cron.log# # Note: The line must be added before the following entry if it exists in "/etc/rsyslog.conf":# # *.* ~ # discards everything#
#
######

require 'spec_helper'

describe '::rhel_07_021100' do
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
