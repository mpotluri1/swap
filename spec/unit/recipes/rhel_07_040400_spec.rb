#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040400
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000250-GPOS-00093 ####
#
# STIG ID: RHEL-07-040400
#
# Rule ID: SV-86877r2_rule
#
# Vuln ID: V-72253
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001453# The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.# NIST SP 800-53 :: AC-17 (2)# NIST SP 800-53A :: AC-17 (2).1# NIST SP 800-53 Revision 4 :: AC-17 (2)# ######

### The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms. ###
# DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.

######
#
# Check:
#
# Verify the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers.# # Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.# # Check that the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers with the following command:# # # grep -i macs /etc/ssh/sshd_config# MACs hmac-sha2-256,hmac-sha2-512# # If any ciphers other than "hmac-sha2-256" or "hmac-sha2-512" are listed or the retuned line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "MACs" keyword and set its value to "hmac-sha2-256" and/or "hmac-sha2-512" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):# # MACs hmac-sha2-256,hmac-sha2-512# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040400' do
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
