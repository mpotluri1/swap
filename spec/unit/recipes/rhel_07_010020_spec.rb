#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010020
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-010020
#
# Rule ID: SV-86479r2_rule
#
# Vuln ID: V-71855
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000663# The organization (or information system) enforces explicit rules governing the installation of software by users.# NIST SP 800-53 :: SA-7# NIST SP 800-53A :: SA-7.1 (ii)# ######

### The cryptographic hash of system files and commands must match vendor values. ###
# Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.# # Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.

######
#
# Check:
#
# Verify the cryptographic hash of system files and commands match the vendor values.# # Check the cryptographic hash of system files and commands with the following command:# # Note: System configuration files (indicated by a "c" in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.# # # rpm -Va | grep '^..5'# # If there is any output from the command for system binaries, this is a finding.#
#
######
#
# Fix:
#
# Run the following command to determine which package owns the file:# # # rpm -qf <filename># # The package can be reinstalled from a yum repository using the command:# # # sudo yum reinstall <packagename># # Alternatively, the package can be reinstalled from trusted media using the command:# # # sudo rpm -Uvh <packagename>#
#
######

require 'spec_helper'

describe '::rhel_07_010020' do
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
