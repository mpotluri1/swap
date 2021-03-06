#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021021
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021021
#
# Rule ID: SV-87813r1_rule
#
# Vuln ID: V-73161
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### File systems that are being imported via Network File System (NFS) must be mounted to prevent binary files from being executed. ###
# The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

######
#
# Check:
#
# Verify file systems that are being NFS exported are mounted with the "noexec" option.# # Find the file system(s) that contain the directories being exported with the following command:# # # more /etc/fstab | grep nfs# # UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs           rw,noexec                                                    0 0# # If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, and use of NFS exported binaries is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.#
#
######
#
# Fix:
#
# Configure the "/etc/fstab" to use the "noexec" option on file systems that are being exported via NFS.#
#
######

require 'spec_helper'

describe '::rhel_07_021021' do
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
