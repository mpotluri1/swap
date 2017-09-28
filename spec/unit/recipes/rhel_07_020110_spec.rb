#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020110
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000114-GPOS-00059 ####
#
# STIG ID: RHEL-07-020110
#
# Rule ID: SV-86609r1_rule
#
# Vuln ID: V-71985
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# # CCI-000778# The information system uniquely identifies an organization defined list of specific and/or types of devices before establishing a local, remote, or network connection.# NIST SP 800-53 :: IA-3# NIST SP 800-53A :: IA-3.1 (ii)# NIST SP 800-53 Revision 4 :: IA-3# # CCI-001958# The information system authenticates an organization defined list of specific and/or types of devices before establishing a local, remote, or network connection.# NIST SP 800-53 Revision 4 :: IA-3# ######

### File system automounter must be disabled unless required. ###
# Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.# # Satisfies: SRG-OS-000114-GPOS-00059, SRG-OS-000378-GPOS-00163, SRG-OS-000480-GPOS-00227

######
#
# Check:
#
# Verify the operating system disables the ability to automount devices.# # Check to see if automounter service is active with the following command:# # # systemctl status autofs# autofs.service - Automounts filesystems on demand# Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)# Active: inactive (dead)# # If the "autofs" status is set to "active" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to disable the ability to automount devices.# # Turn off the automount service with the following command:# # # systemctl disable autofs# # If "autofs" is required for Network File System (NFS), it must be documented with the ISSO.#
#
######

require 'spec_helper'

describe '::rhel_07_020110' do
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
