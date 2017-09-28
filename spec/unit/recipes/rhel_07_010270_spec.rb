#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010270
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000077-GPOS-00045 ####
#
# STIG ID: RHEL-07-010270
#
# Rule ID: SV-86557r1_rule
#
# Vuln ID: V-71933
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000200# The information system prohibits password reuse for the organization defined number of generations.# NIST SP 800-53 :: IA-5 (1) (e)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (e)# ######

### Passwords must be prohibited from reuse for a minimum of five generations. ###
# Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.

######
#
# Check:
#
# Verify the operating system prohibits password reuse for a minimum of five generations.# # Check for the value of the "remember" argument in "/etc/pam.d/system-auth-ac" with the following command:# # # grep -i remember /etc/pam.d/system-auth-ac# password sufficient pam_unix.so use_authtok sha512 shadow remember=5# # If the line containing the "pam_unix.so" line does not have the "remember" module argument set, or the value of the "remember" module argument is set to less than "5", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to prohibit password reuse for a minimum of five generations.# # Add the following line in "/etc/pam.d/system-auth-ac" (or modify the line to have the required value):# # password sufficient pam_unix.so use_authtok sha512 shadow remember=5# # and run the "authconfig" command.#
#
######

require 'spec_helper'

describe '::rhel_07_010270' do
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
