#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010119
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000069-GPOS-00037 ####
#
# STIG ID: RHEL-07-010119
#
# Rule ID: SV-87811r2_rule
#
# Vuln ID: V-73159
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000192# The information system enforces password complexity by the minimum number of upper case characters used.# NIST SP 800-53 :: IA-5 (1) (a)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (a)# ######

### When passwords are changed or new passwords are established, pwquality must be used. ###
# Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "Pwquality" enforces complex password construction configuration on the system.

######
#
# Check:
#
# Verify the operating system uses "pwquality" to enforce the password complexity rules.# # Check for the use of "pwquality" with the following command:# # # grep pwquality /etc/pam.d/passwd# # password    required    pam_pwquality.so retry=3# # If the command does not return a line containing the value "pam_pwquality.so", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to use "pwquality" to enforce password complexity rules.# # Add the following line to "/etc/pam.d/passwd" (or modify the line to have the required value):# # password    required    pam_pwquality.so retry=3#
#
######

require 'spec_helper'

describe '::rhel_07_010119' do
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
