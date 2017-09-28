#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040390
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000074-GPOS-00042 ####
#
# STIG ID: RHEL-07-040390
#
# Rule ID: SV-86875r2_rule
#
# Vuln ID: V-72251
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000197# The information system, for password-based authentication, transmits only encrypted representations of passwords.# NIST SP 800-53 :: IA-5 (1) (c)# NIST SP 800-53A :: IA-5 (1).1 (v)# NIST SP 800-53 Revision 4 :: IA-5 (1) (c)# # CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The SSH daemon must be configured to only use the SSHv2 protocol. ###
# SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.# # Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227

######
#
# Check:
#
# Verify the SSH daemon is configured to only use the SSHv2 protocol.# # Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:# # # grep -i protocol /etc/ssh/sshd_config# Protocol 2# #Protocol 1,2# # If any protocol line other than "Protocol 2" is uncommented, this is a finding.#
#
######
#
# Fix:
#
# Remove all Protocol lines that reference version "1" in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The "Protocol" line must be as follows:# # Protocol 2# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040390' do
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
