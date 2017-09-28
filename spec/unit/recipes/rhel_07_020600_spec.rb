#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020600
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020600
#
# Rule ID: SV-86635r1_rule
#
# Vuln ID: V-72011
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive users must have a home directory assigned in the /etc/passwd file. ###
# If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.

######
#
# Check:
#
# Verify local interactive users on the system have a home directory assigned.# # Check for missing local interactive user home directories with the following command:# # # pwck -r# user 'lp': directory '/var/spool/lpd' does not exist# user 'news': directory '/var/spool/news' does not exist# user 'uucp': directory '/var/spool/uucp' does not exist# user 'smithj': directory '/home/smithj' does not exist# # Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:# # # cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"# # If any interactive users do not have a home directory assigned, this is a finding.#
#
######
#
# Fix:
#
# Assign home directories to all local interactive users that currently do not have a home directory assigned.#
#
######

require 'spec_helper'

describe '::rhel_07_020600' do
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
