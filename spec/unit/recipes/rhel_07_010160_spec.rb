#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010160
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000072-GPOS-00040 ####
#
# STIG ID: RHEL-07-010160
#
# Rule ID: SV-86535r1_rule
#
# Vuln ID: V-71911
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000195# The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.# NIST SP 800-53 :: IA-5 (1) (b)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (b)# ######

### When passwords are changed a minimum of eight of the total number of characters must be changed. ###
# Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.# # Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

######
#
# Check:
#
# The "difok" option sets the number of characters in a password that must not be present in the old password.# # Check for the value of the "difok" option in "/etc/security/pwquality.conf" with the following command:# # # grep difok /etc/security/pwquality.conf# difok = 8# # If the value of "difok" is set to less than "8", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.# # Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):# # difok = 8#
#
######

require 'spec_helper'

describe '::rhel_07_010160' do
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
