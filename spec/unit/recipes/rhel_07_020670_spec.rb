#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020670
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020670
#
# Rule ID: SV-86649r1_rule
#
# Vuln ID: V-72025
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All files and directories contained in local interactive user home directories must be group-owned by a group of which the home directory owner is a member. ###
# If a local interactive user’s files are group-owned by a group of which the user is not a member, unintended users may be able to access them.

######
#
# Check:
#
# Verify all files and directories in a local interactive user home directory are group-owned by a group the user is a member of.# # Check the group owner of all files and directories in a local interactive user’s home directory with the following command:# # Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".# # # ls -lLR /<home directory>/<users home directory>/# -rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1# -rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2# -rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3# # If any files are found with an owner different than the group home directory user, check to see if the user is a member of that group with the following command:# # # grep smithj /etc/group# sa:x:100:juan,shelley,bob,smithj# smithj:x:521:smithj# # If the user is not a member of a group that group owns file(s) in a local interactive user’s home directory, this is a finding.#
#
######
#
# Fix:
#
# Change the group of a local interactive user’s files and directories to a group that the interactive user is a member of. To change the group owner of a local interactive user’s files and directories, use the following command:# # Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.# # # chgrp users /home/smithj/<file>#
#
######

require 'spec_helper'

describe '::rhel_07_020670' do
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
