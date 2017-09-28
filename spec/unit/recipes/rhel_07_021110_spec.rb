#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021110
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021110
#
# Rule ID: SV-86677r1_rule
#
# Vuln ID: V-72053
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### If the cron.allow file exists it must be owned by root. ###
# If the owner of the "cron.allow" file is not set to root, the possibility exists for an unauthorized user to view or to edit sensitive information.

######
#
# Check:
#
# Verify that the "cron.allow" file is owned by root.# # Check the owner of the "cron.allow" file with the following command:# # # l s -al /etc/cron.allow# -rw------- 1 root root 6 Mar  5  2011 /etc/cron.allow# # If the "cron.allow" file exists and has an owner other than root, this is a finding.#
#
######
#
# Fix:
#
# Set the owner on the "/etc/cron.allow" file to root with the following command:# # # chown root /etc/cron.allow#
#
######

require 'spec_helper'

describe '::rhel_07_021110' do
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
