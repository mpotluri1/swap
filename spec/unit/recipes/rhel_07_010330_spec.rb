#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010330
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000329-GPOS-00128 ####
#
# STIG ID: RHEL-07-010330
#
# Rule ID: SV-86569r1_rule
#
# Vuln ID: V-71945
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002238# The information system automatically locks the account or node for either an organization-defined time period, until the locked account or node is released by an administrator, or delays the next login prompt according to the organization-defined delay algorithm when the maximum number of unsuccessful attempts is exceeded.# NIST SP 800-53 Revision 4 :: AC-7 b# ######

### If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked. ###
# By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.# # Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005

######
#
# Check:
#
# Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.# # # grep pam_faillock.so /etc/pam.d/password-auth-ac# auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900# auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900# # If the "even_deny_root" setting is not defined on both lines with the "pam_faillock.so" module name, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to automatically lock the root account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.# # Modify the first three lines of the auth section of the "/etc/pam.d/system-auth-ac" and "/etc/pam.d/password-auth-ac" files to match the following lines:# # auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800# auth        sufficient     pam_unix.so try_first_pass# auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800# # and run the "authconfig" command.#
#
######

require 'spec_helper'

describe '::rhel_07_010330' do
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
