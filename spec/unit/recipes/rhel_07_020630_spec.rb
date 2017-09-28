#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020630
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020630
#
# Rule ID: SV-86641r1_rule
#
# Vuln ID: V-72017
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive user home directories must have mode 0750 or less permissive. ###
# Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.

######
#
# Check:
#
# Verify the assigned home directory of all local interactive users has a mode of "0750" or less permissive.# # Check the home directory assignment for all non-privileged users on the system with the following command:# # Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.# # # ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)# -rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj# # If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.#
#
######
#
# Fix:
#
# Change the mode of interactive user’s home directories to "0750". To change the mode of a local interactive user’s home directory, use the following command:# # Note: The example will be for the user "smithj".# # # chmod 0750 /home/smithj#
#
######

require 'spec_helper'

describe '::rhel_07_020630' do
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
