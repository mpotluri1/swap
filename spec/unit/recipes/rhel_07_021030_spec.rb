#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021030
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021030
#
# Rule ID: SV-86671r1_rule
#
# Vuln ID: V-72047
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### All world-writable directories must be group-owned by root, sys, bin, or an application group. ###
# If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.# # The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.

######
#
# Check:
#
# Verify all world-writable directories are group-owned by root, sys, bin, or an application group.# # Check the system for world-writable directories with the following command:# # Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.# # # find / -perm -002 -xdev -type d -fstype xfs -exec ls -lLd {} \;# drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue# drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm# drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp# # If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding.#
#
######
#
# Fix:
#
# Change the group of the world-writable directories to root with the following command:# # # chgrp root <directory>#
#
######

require 'spec_helper'

describe '::rhel_07_021030' do
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
