#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021340
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021340
#
# Rule ID: SV-86689r1_rule
#
# Vuln ID: V-72065
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must use a separate file system for /tmp (or equivalent). ###
# The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

######
#
# Check:
#
# Verify that a separate file system/partition has been created for "/tmp".# # Check that a file system/partition has been created for "/tmp" with the following command:# # # systemctl is-enabled tmp.mount# enabled# # If the "tmp.mount" service is not enabled, this is a finding.#
#
######
#
# Fix:
#
# Start the "tmp.mount" service with the following command:# # # systemctl enable tmp.mount#
#
######

require 'spec_helper'

describe '::rhel_07_021340' do
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
