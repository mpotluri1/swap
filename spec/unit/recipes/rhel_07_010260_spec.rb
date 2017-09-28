#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010260
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000076-GPOS-00044 ####
#
# STIG ID: RHEL-07-010260
#
# Rule ID: SV-86555r1_rule
#
# Vuln ID: V-71931
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000199# The information system enforces maximum password lifetime restrictions.# NIST SP 800-53 :: IA-5 (1) (d)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (d)# ######

### Existing passwords must be restricted to a 60-day maximum lifetime. ###
# Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.

######
#
# Check:
#
# Check whether the maximum time period for existing passwords is restricted to 60 days.# # # awk -F: '$5 > 60 {print $1}' /etc/shadow# # If any results are returned that are not associated with a system account, this is a finding.#
#
######
#
# Fix:
#
# Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.# # # chage -M 60 [user]#
#
######

require 'spec_helper'

describe '::rhel_07_010260' do
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
