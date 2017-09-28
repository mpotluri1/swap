#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020650
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020650
#
# Rule ID: SV-86645r2_rule
#
# Vuln ID: V-72021
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive user home directories must be group-owned by the home directory owners primary group. ###
# If the Group Identifier (GID) of a local interactive user’s home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user’s files, and users that share the same group may not be able to access files that they legitimately should.

######
#
# Check:
#
# Verify the assigned home directory of all local interactive users is group-owned by that user’s primary GID.# # Check the home directory assignment for all non-privileged users on the system with the following command:# # Note: This may miss local interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.# # # ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)# -rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj# # Check the user's primary group with the following command:# # # grep users /etc/group# users:x:250:smithj,jonesj,jacksons# # If the user home directory referenced in "/etc/passwd" is not group-owned by that user’s primary GID, this is a finding.#
#
######
#
# Fix:
#
# Change the group owner of a local interactive user’s home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user’s home directory, use the following command:# # Note: The example will be for the user "smithj", who has a home directory of "/home/smithj", and has a primary group of users.# # # chgrp users /home/smithj#
#
######

require 'spec_helper'

describe '::rhel_07_020650' do
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
