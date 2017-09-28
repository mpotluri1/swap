#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020720
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020720
#
# Rule ID: SV-86659r2_rule
#
# Vuln ID: V-72035
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All local interactive user initialization files executable search paths must contain only paths that resolve to the users home directory. ###
# The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user’s home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).

######
#
# Check:
#
# Verify that all local interactive user initialization files' executable search path statements do not contain statements that will reference a working directory other than the users’ home directory.# # Check the executable search path statement for all local interactive user initialization files in the users' home directory with the following commands:# # Note: The example will be for the smithj user, which has a home directory of "/home/smithj".# # # grep -i path /home/smithj/.*# /home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin# /home/smithj/.bash_profile:export PATH# # If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, this is a finding.#
#
######
#
# Fix:
#
# Configure the "/etc/fstab" to use the "nosuid" option on file systems that contain user home directories for interactive users.#
#
######

require 'spec_helper'

describe '::rhel_07_020720' do
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
