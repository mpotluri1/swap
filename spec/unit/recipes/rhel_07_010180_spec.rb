#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010180
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000072-GPOS-00040 ####
#
# STIG ID: RHEL-07-010180
#
# Rule ID: SV-86539r1_rule
#
# Vuln ID: V-71915
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000195# The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.# NIST SP 800-53 :: IA-5 (1) (b)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (b)# ######

### When passwords are changed the number of repeating consecutive characters must not be more than four characters. ###
# Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.# # Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

######
#
# Check:
#
# The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.# # Check for the value of the "maxrepeat" option in "/etc/security/pwquality.conf" with the following command:# # # grep maxrepeat /etc/security/pwquality.conf# maxrepeat = 2# # If the value of "maxrepeat" is set to more than "2", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.# # Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):# # maxrepeat = 2#
#
######

require 'spec_helper'

describe '::rhel_07_010180' do
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
