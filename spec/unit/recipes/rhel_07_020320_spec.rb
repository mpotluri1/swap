#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020320
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020320
#
# Rule ID: SV-86631r1_rule
#
# Vuln ID: V-72007
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002165# The information system enforces organization-defined discretionary access control policies over defined subjects and objects.# NIST SP 800-53 Revision 4 :: AC-3 (4)# ######

### All files and directories must have a valid owner. ###
# Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier "UID" as the UID of the un-owned files.

######
#
# Check:
#
# Verify all files and directories on the system have a valid owner.# # Check the owner of all files and directories with the following command:# # Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.# # # find / -xdev -fstype xfs -nouser# # If any files on the system do not have an assigned owner, this is a finding.#
#
######
#
# Fix:
#
# Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the "chown" command:# # # chown <user> <file>#
#
######

require 'spec_helper'

describe '::rhel_07_020320' do
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
