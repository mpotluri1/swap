#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010120
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000069-GPOS-00037 ####
#
# STIG ID: RHEL-07-010120
#
# Rule ID: SV-86527r2_rule
#
# Vuln ID: V-71903
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000192# The information system enforces password complexity by the minimum number of upper case characters used.# NIST SP 800-53 :: IA-5 (1) (a)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (a)# ######

### When passwords are changed or new passwords are established, the new password must contain at least one upper-case character. ###
# Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.# # Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

######
#
# Check:
#
# Note: The value to require a number of upper-case characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".# # Check the value for "ucredit" in "/etc/security/pwquality.conf" with the following command:# # # grep ucredit /etc/security/pwquality.conf# ucredit = -1# # If the value of "ucredit" is not set to a negative value, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to enforce password complexity by requiring that at least one upper-case character be used by setting the "ucredit" option.# # Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):# # ucredit = -1#
#
######

require 'spec_helper'

describe '::rhel_07_010120' do
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
