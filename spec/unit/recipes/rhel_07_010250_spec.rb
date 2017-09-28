#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010250
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000076-GPOS-00044 ####
#
# STIG ID: RHEL-07-010250
#
# Rule ID: SV-86553r1_rule
#
# Vuln ID: V-71929
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000199# The information system enforces maximum password lifetime restrictions.# NIST SP 800-53 :: IA-5 (1) (d)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)# ######

### Passwords for new users must be restricted to a 60-day maximum lifetime. ###
# Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

######
#
# Check:
#
# Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.# # Check for the value of "PASS_MAX_DAYS" in "/etc/login.defs" with the following command:# # # grep -i pass_max_days /etc/login.defs# PASS_MAX_DAYS     60# # If the "PASS_MAX_DAYS" parameter value is not 60 or less, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to enforce a 60-day maximum password lifetime restriction.# # Add the following line in "/etc/login.defs" (or modify the line to have the required value):# # PASS_MAX_DAYS     60#
#
######

require 'spec_helper'

describe '::rhel_07_010250' do
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
