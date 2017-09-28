#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_031000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-031000
#
# Rule ID: SV-86833r1_rule
#
# Vuln ID: V-72209
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must send rsyslog output to a log aggregation server. ###
# Sending rsyslog output to another system ensures that the logs cannot be removed or modified in the event that the system is compromised or has a hardware failure.

######
#
# Check:
#
# Verify "rsyslog" is configured to send all messages to a log aggregation server.# # Check the configuration of "rsyslog" with the following command:# # Note: If another logging package is used, substitute the utility configuration file for "/etc/rsyslog.conf".# # # grep @ /etc/rsyslog.conf# *.* @@logagg.site.mil# # If there are no lines in the "/etc/rsyslog.conf" file that contain the "@" or "@@" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all "rsyslog" output, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.# # If there is no evidence that the audit logs are being sent to another system, this is a finding.#
#
######
#
# Fix:
#
# Modify the "/etc/rsyslog.conf" file to contain a configuration line to send all "rsyslog" output to a log aggregation system:# # *.* @@<log aggregation system name>#
#
######

require 'spec_helper'

describe '::rhel_07_031000' do
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
