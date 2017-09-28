#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020330
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020330
#
# Rule ID: SV-86633r1_rule
#
# Vuln ID: V-72009
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002165# The information system enforces organization-defined discretionary access control policies over defined subjects and objects.# NIST SP 800-53 Revision 4 :: AC-3 (4)# ######

### All files and directories must have a valid group owner. ###
# Files without a valid group owner may be unintentionally inherited if a group is assigned the same Group Identifier (GID) as the GID of the files without a valid group owner.

######
#
# Check:
#
# Verify all files and directories on the system have a valid group.# # Check the owner of all files and directories with the following command:# # Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.# # # find / -xdev -fstype xfs -nogroup# # If any files on the system do not have an assigned group, this is a finding.#
#
######
#
# Fix:
#
# Either remove all files and directories from the system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:# # # chgrp <group> <file>#
#
######

require 'spec_helper'

describe '::rhel_07_020330' do
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
