#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040110
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000033-GPOS-00014 ####
#
# STIG ID: RHEL-07-040110
#
# Rule ID: SV-86845r2_rule
#
# Vuln ID: V-72221
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000068# The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.# NIST SP 800-53 :: AC-17 (2)# NIST SP 800-53A :: AC-17 (2).1# NIST SP 800-53 Revision 4 :: AC-17 (2)# # CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# # CCI-000803# The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.# NIST SP 800-53 :: IA-7# NIST SP 800-53A :: IA-7.1# NIST SP 800-53 Revision 4 :: IA-7# ######

### A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications. ###
# Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.# # Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.# # FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.# # Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000120-GPOS-00061, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173

######
#
# Check:
#
# Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.# # Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.# # The location of the "sshd_config" file may vary if a different daemon is in use.# # Inspect the "Ciphers" configuration with the following command:# # # grep -i ciphers /etc/ssh/sshd_config# Ciphers aes128-ctr,aes192-ctr,aes256-ctr# # If any ciphers other than "aes128-ctr", "aes192-ctr", or "aes256-ctr" are listed, the "Ciphers" keyword is missing, or the retuned line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure SSH to use FIPS 140-2 approved cryptographic algorithms.# # Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).# # Ciphers aes128-ctr,aes192-ctr,aes256-ctr# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040110' do
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
