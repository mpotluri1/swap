#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010190
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000072-GPOS-00040 ####
#
# STIG ID: RHEL-07-010190
#
# Rule ID: SV-86541r1_rule
#
# Vuln ID: V-71917
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000195# The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.# NIST SP 800-53 :: IA-5 (1) (b)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (b)# ######

### When passwords are changed the number of repeating characters of the same character class must not be more than four characters. ###
# Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.# # Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

######
#
# Check:
#
# The "maxclassrepeat" option sets the maximum number of allowed same consecutive characters in the same class in the new password.# # Check for the value of the "maxclassrepeat" option in "/etc/security/pwquality.conf" with the following command:# # # grep maxclassrepeat /etc/security/pwquality.conf# maxclassrepeat = 4# # If the value of "maxclassrepeat" is set to more than "4", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option.# # Add the following line to "/etc/security/pwquality.conf" conf (or modify the line to have the required value):# # maxclassrepeat = 4#
#
######

require 'spec_helper'

describe '::rhel_07_010190' do
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
