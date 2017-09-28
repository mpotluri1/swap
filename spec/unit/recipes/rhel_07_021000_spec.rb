#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021000
#
# Rule ID: SV-86665r2_rule
#
# Vuln ID: V-72041
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### File systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed. ###
# The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

######
#
# Check:
#
# Verify file systems that contain user home directories are mounted with the "nosuid" option.# # Find the file system(s) that contain the user home directories with the following command:# # Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.# # # cut -d: -f 1,6 /etc/passwd | egrep ":[1-4][0-9]{3}"# smithj:/home/smithj# thomasr:/home/thomasr# # Check the file systems that are mounted at boot time with the following command:# # # more /etc/fstab# # UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home   ext4   rw,relatime,discard,data=ordered,nosuid 0 2# # If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "nosuid" option set, this is a finding.#
#
######
#
# Fix:
#
# Configure the "/etc/fstab" to use the "nosuid" option on file systems that contain user home directories.#
#
######

require 'spec_helper'

describe '::rhel_07_021000' do
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
