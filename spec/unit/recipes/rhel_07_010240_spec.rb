#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010240
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000075-GPOS-00043 ####
#
# STIG ID: RHEL-07-010240
#
# Rule ID: SV-86551r1_rule
#
# Vuln ID: V-71927
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000198# The information system enforces minimum password lifetime restrictions.# NIST SP 800-53 :: IA-5 (1) (d)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)# ######

### Passwords must be restricted to a 24 hours/1 day minimum lifetime. ###
# Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

######
#
# Check:
#
# Check whether the minimum time period between password changes for each user account is one day or greater.# # # awk -F: '$4 < 1 {print $1}' /etc/shadow# # If any results are returned that are not associated with a system account, this is a finding.#
#
######
#
# Fix:
#
# Configure non-compliant accounts to enforce a 24 hours/1 day minimum password lifetime:# # # chage -m 1 [user]#
#
######

require 'spec_helper'

describe '::rhel_07_010240' do
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
