#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010280
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000078-GPOS-00046 ####
#
# STIG ID: RHEL-07-010280
#
# Rule ID: SV-86559r1_rule
#
# Vuln ID: V-71935
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000205# The information system enforces minimum password length.# NIST SP 800-53 :: IA-5 (1) (a)# NIST SP 800-53A :: IA-5 (1).1 (i)# NIST SP 800-53 Revision 4 :: IA-5 (1) (a)# ######

### Passwords must be a minimum of 15 characters in length. ###
# The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.# # Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

######
#
# Check:
#
# Verify the operating system enforces a minimum 15-character password length. The "minlen" option sets the minimum number of characters in a new password.# # Check for the value of the "minlen" option in "/etc/security/pwquality.conf" with the following command:# # # grep minlen /etc/security/pwquality.conf# minlen = 15# # If the command does not return a "minlen" value of 15 or greater, this is a finding.#
#
######
#
# Fix:
#
# Configure operating system to enforce a minimum 15-character password length.# # Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):# # minlen = 15#
#
######

require 'spec_helper'

describe '::rhel_07_010280' do
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
