#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020250
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020250
#
# Rule ID: SV-86621r2_rule
#
# Vuln ID: V-71997
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The operating system must be a vendor supported release. ###
# An operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

######
#
# Check:
#
# Verify the version of the operating system is vendor supported.# # Check the version of the operating system with the following command:# # # cat /etc/redhat-release# # Red Hat Enterprise Linux Server release 7.2 (Maipo)# # Current End of Life for RHEL 7.2 is Q4 2020.# # Current End of Life for RHEL 7.3 is 30 June 2024.# # If the release is not supported by the vendor, this is a finding.#
#
######
#
# Fix:
#
# Upgrade to a supported version of the operating system.#
#
######

require 'spec_helper'

describe '::rhel_07_020250' do
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
