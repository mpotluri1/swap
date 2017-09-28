#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020620
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020620
#
# Rule ID: SV-86639r1_rule
#
# Vuln ID: V-72015
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive user home directories defined in the /etc/passwd file must exist. ###
# If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.

######
#
# Check:
#
# Verify the assigned home directory of all local interactive users on the system exists.# # Check the home directory assignment for all local interactive non-privileged users on the system with the following command:# # # cut -d: -f 1,3 /etc/passwd | egrep ":[1-9][0-9]{2}$|:[0-9]{1,2}$"# smithj /home/smithj# # Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.# # Check that all referenced home directories exist with the following command:# # # pwck -r# user 'smithj': directory '/home/smithj' does not exist# # If any home directories referenced in "/etc/passwd" are returned as not defined, this is a finding.#
#
######
#
# Fix:
#
# Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":# # Note: The example will be for the user smithj, who has a home directory of "/home/smithj", a UID of "smithj", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".# # # mkdir /home/smithj# # chown smithj /home/smithj# # chgrp users /home/smithj# # chmod 0750 /home/smithj#
#
######

require 'spec_helper'

describe '::rhel_07_020620' do
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
