#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020710
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020710
#
# Rule ID: SV-86657r1_rule
#
# Vuln ID: V-72033
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local initialization files must have mode 0740 or less permissive. ###
# Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

######
#
# Check:
#
# Verify that all local initialization files have a mode of "0740" or less permissive.# # Check the mode on all local initialization files with the following command:# # Note: The example will be for the smithj user, who has a home directory of "/home/smithj".# # # ls -al /home/smithj/.* | more# -rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile# -rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login# -rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something# # If any local initialization files have a mode more permissive than "0740", this is a finding.#
#
######
#
# Fix:
#
# Set the mode of the local initialization files to "0740" with the following command:# # Note: The example will be for the smithj user, who has a home directory of "/home/smithj".# # # chmod 0740 /home/smithj/.<INIT_FILE>#
#
######

require 'spec_helper'

describe '::rhel_07_020710' do
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
