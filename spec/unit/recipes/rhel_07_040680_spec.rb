#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040680
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040680
#
# Rule ID: SV-86921r2_rule
#
# Vuln ID: V-72297
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must be configured to prevent unrestricted mail relaying. ###
# If unrestricted mail relaying is permitted, unauthorized senders could use this host as a mail relay for the purpose of sending spam or other unauthorized activity.

######
#
# Check:
#
# Verify the system is configured to prevent unrestricted mail relaying.# # Determine if "postfix" is installed with the following commands:# # # yum list installed postfix# postfix-2.6.6-6.el7.x86_64.rpm# # If postfix is not installed, this is Not Applicable.# # If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:# # # postconf -n smtpd_client_restrictions# smtpd_client_restrictions = permit_mynetworks, reject# # If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.#
#
######
#
# Fix:
#
# If "postfix" is installed, modify the "/etc/postfix/main.cf" file to restrict client connections to the local network with the following command:# # # postconf -e 'smtpd_client_restrictions = permit_mynetworks,reject'#
#
######

require 'spec_helper'

describe '::rhel_07_040680' do
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
