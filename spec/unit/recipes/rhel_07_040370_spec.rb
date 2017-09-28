#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040370
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040370
#
# Rule ID: SV-86871r2_rule
#
# Vuln ID: V-72247
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not permit direct logons to the root account using remote access via SSH. ###
# Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.

######
#
# Check:
#
# Verify remote access using SSH prevents users from logging on directly as root.# # Check that SSH prevents users from logging on directly as root with the following command:# # # grep -i permitrootlogin /etc/ssh/sshd_config# PermitRootLogin no# # If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure SSH to stop users from logging on remotely as the root user.# # Edit the appropriate  "/etc/ssh/sshd_config" file to uncomment or add the line for the "PermitRootLogin" keyword and set its value to "no" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):# # PermitRootLogin no# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040370' do
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
