#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021010
#
# Rule ID: SV-86667r1_rule
#
# Vuln ID: V-72043
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### File systems that are used with removable media must be mounted to prevent files with the setuid and setgid bit set from being executed. ###
# The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

######
#
# Check:
#
# Verify file systems that are used for removable media are mounted with the "nouid" option.# # Check the file systems that are mounted at boot time with the following command:# # # more /etc/fstab# # UUID=2bc871e4-e2a3-4f29-9ece-3be60c835222     /mnt/usbflash      vfat   noauto,owner,ro,nosuid                        0 0# # If a file system found in "/etc/fstab" refers to removable media and it does not have the "nosuid" option set, this is a finding.#
#
######
#
# Fix:
#
# Configure the "/etc/fstab" to use the "nosuid" option on file systems that are associated with removable media.#
#
######

require 'spec_helper'

describe '::rhel_07_021010' do
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
