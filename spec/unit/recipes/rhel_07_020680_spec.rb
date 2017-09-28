#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020680
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020680
#
# Rule ID: SV-86651r1_rule
#
# Vuln ID: V-72027
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All files and directories contained in local interactive user home directories must have mode 0750 or less permissive. ###
# If a local interactive user files have excessive permissions, unintended users may be able to access or modify them.

######
#
# Check:
#
# Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".# # Check the mode of all non-initialization files in a local interactive user home directory with the following command:# # Files that begin with a "." are excluded from this requirement.# # Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".# # # ls -lLR /home/smithj# -rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1# -rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2# -rw-r-x--- 1 smithj smithj 231 Mar  5 17:06 file3# # If any files are found with a mode more permissive than "0750", this is a finding.#
#
######
#
# Fix:
#
# Set the mode on files and directories in the local interactive user home directory with the following command:# # Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.# # # chmod 0750 /home/smithj/<file>#
#
######

require 'spec_helper'

describe '::rhel_07_020680' do
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
