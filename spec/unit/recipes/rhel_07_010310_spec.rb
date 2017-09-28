#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010310
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000118-GPOS-00060 ####
#
# STIG ID: RHEL-07-010310
#
# Rule ID: SV-86565r1_rule
#
# Vuln ID: V-71941
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000795# The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.# NIST SP 800-53 :: IA-4 e# NIST SP 800-53A :: IA-4.1 (iii)# NIST SP 800-53 Revision 4 :: IA-4 e# ######

### The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires. ###
# Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.# # Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.

######
#
# Check:
#
# Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:# # # grep -i inactive /etc/default/useradd# INACTIVE=0# # If the value is not set to "0", is commented out, or is not defined, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after the password expires.# # Add the following line to "/etc/default/useradd" (or modify the line to have the required value):# # INACTIVE=0#
#
######

require 'spec_helper'

describe '::rhel_07_010310' do
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
