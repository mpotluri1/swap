#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021300
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021300
#
# Rule ID: SV-86681r1_rule
#
# Vuln ID: V-72057
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Kernel core dumps must be disabled unless needed. ###
# Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.

######
#
# Check:
#
# Verify that kernel core dumps are disabled unless needed.# # Check the status of the "kdump" service with the following command:# # # systemctl status kdump.service# kdump.service - Crash recovery kernel arming# Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)# Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago# Main PID: 1130 (code=exited, status=0/SUCCESS)# kernel arming.# # If the "kdump" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).# # If the service is active and is not documented, this is a finding.#
#
######
#
# Fix:
#
# If kernel core dumps are not required, disable the "kdump" service with the following command:# # # systemctl disable kdump.service# # If kernel core dumps are required, document the need with the ISSO.#
#
######

require 'spec_helper'

describe '::rhel_07_021300' do
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
