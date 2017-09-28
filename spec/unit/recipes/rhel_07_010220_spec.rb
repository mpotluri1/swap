#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010220
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000073-GPOS-00041 ####
#
# STIG ID: RHEL-07-010220
#
# Rule ID: SV-86547r2_rule
#
# Vuln ID: V-71923
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000196# The information system, for password-based authentication, stores only encrypted representations of passwords.# NIST SP 800-53 :: IA-5 (1) (c)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (c)# ######

### User and group account administration utilities must be configured to store only encrypted representations of passwords. ###
# Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.

######
#
# Check:
#
# Verify the user and group account administration utilities are configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is "SHA512".# # Check that the system is configured to create "SHA512" hashed passwords with the following command:# # # cat /etc/libuser.conf | grep -i sha512# # crypt_style = sha512# # If the "crypt_style" variable is not set to "sha512", is not in the defaults section, or does not exist, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to store only SHA512 encrypted representations of passwords.# # Add or update the following line in "/etc/libuser.conf" in the [defaults] section:# # crypt_style = sha512#
#
######

require 'spec_helper'

describe '::rhel_07_010220' do
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
