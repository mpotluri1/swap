#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020730
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020730
#
# Rule ID: SV-86661r1_rule
#
# Vuln ID: V-72037
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Local initialization files must not execute world-writable programs. ###
# If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.

######
#
# Check:
#
# Verify that local initialization files do not execute world-writable programs.# # Check the system for world-writable files with the following command:# # # find / -perm -002 -type f -exec ls -ld {} \; | more# # For all files listed, check for their presence in the local initialization files with the following commands:# # Note: The example will be for a system that is configured to create users’ home directories in the "/home" directory.# # # grep <file> /home/*/.*# # If any local initialization files are found to reference world-writable files, this is a finding.#
#
######
#
# Fix:
#
# Set the mode on files being executed by the local initialization files with the following command:# # # chmod 0755  <file>#
#
######

require 'spec_helper'

describe '::rhel_07_020730' do
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
