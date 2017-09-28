#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040180
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000250-GPOS-00093 ####
#
# STIG ID: RHEL-07-040180
#
# Rule ID: SV-86851r2_rule
#
# Vuln ID: V-72227
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001453# The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.# NIST SP 800-53 :: AC-17 (2)# NIST SP 800-53A :: AC-17 (2).1# NIST SP 800-53 Revision 4 :: AC-17 (2)# ######

### The operating system must implement cryptography to protect the integrity of Lightweight Directory Access Protocol (LDAP) authentication communications. ###
# Without cryptographic integrity protections, information can be altered by unauthorized users without detection.# # Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.

######
#
# Check:
#
# Verify the operating system implements cryptography to protect the integrity of remote LDAP authentication sessions.# # To determine if LDAP is being used for authentication, use the following command:# # # grep -i useldapauth /etc/sysconfig/authconfig# USELDAPAUTH=yes# # If USELDAPAUTH=yes, then LDAP is being used. To see if LDAP is configured to use TLS, use the following command:# # # grep -i ssl /etc/pam_ldap.conf# ssl start_tls# # If the "ssl" option is not "start_tls", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to implement cryptography to protect the integrity of LDAP authentication sessions.# # Set the USELDAPAUTH=yes in "/etc/sysconfig/authconfig".# # Set "ssl start_tls" in "/etc/pam_ldap.conf".#
#
######

require 'spec_helper'

describe '::rhel_07_040180' do
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
