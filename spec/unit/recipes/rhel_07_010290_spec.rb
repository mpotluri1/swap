#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010290
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-010290
#
# Rule ID: SV-86561r1_rule
#
# Vuln ID: V-71937
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not have accounts configured with blank or null passwords. ###
# If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.

######
#
# Check:
#
# To verify that null passwords cannot be used, run the following command:# # # grep nullok /etc/pam.d/system-auth-ac# # If this produces any output, it may be possible to log on with accounts with empty passwords.# # If null passwords can be used, this is a finding.#
#
######
#
# Fix:
#
# If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.# # Remove any instances of the "nullok" option in "/etc/pam.d/system-auth-ac" to prevent logons with empty passwords and run the "authconfig" command.#
#
######

require 'spec_helper'

describe '::rhel_07_010290' do
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
