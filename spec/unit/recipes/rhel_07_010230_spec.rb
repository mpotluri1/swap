#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010230
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000075-GPOS-00043 ####
#
# STIG ID: RHEL-07-010230
#
# Rule ID: SV-86549r1_rule
#
# Vuln ID: V-71925
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000198# The information system enforces minimum password lifetime restrictions.# NIST SP 800-53 :: IA-5 (1) (d)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)# ######

### Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime. ###
# Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

######
#
# Check:
#
# Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.# # Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command:# # # grep -i pass_min_days /etc/login.defs# PASS_MIN_DAYS     1# # If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.# # Add the following line in "/etc/login.defs" (or modify the line to have the required value):# # PASS_MIN_DAYS     1#
#
######

require 'spec_helper'

describe '::rhel_07_010230' do
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
