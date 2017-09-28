#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040540
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040540
#
# Rule ID: SV-86901r1_rule
#
# Vuln ID: V-72277
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### There must be no .shosts files on the system. ###
# The .shosts files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.

######
#
# Check:
#
# Verify there are no ".shosts" files on the system.# # Check the system for the existence of these files with the following command:# # # find / -name '*.shosts'# # If any ".shosts" files are found on the system, this is a finding.#
#
######
#
# Fix:
#
# Remove any found ".shosts" files from the system.# # # rm /[path]/[to]/[file]/.shosts#
#
######

require 'spec_helper'

describe '::rhel_07_040540' do
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
