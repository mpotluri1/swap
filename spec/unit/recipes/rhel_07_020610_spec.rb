#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020610
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020610
#
# Rule ID: SV-86637r1_rule
#
# Vuln ID: V-72013
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive user accounts, upon creation, must be assigned a home directory. ###
# If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

######
#
# Check:
#
# Verify all local interactive users on the system are assigned a home directory upon creation.# # Check to see if the system is configured to create home directories for local interactive users with the following command:# # # grep -i create_home /etc/login.defs# CREATE_HOME yes# # If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.# # CREATE_HOME yes#
#
######

require 'spec_helper'

describe '::rhel_07_020610' do
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
