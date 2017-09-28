#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040710
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040710
#
# Rule ID: SV-86927r2_rule
#
# Vuln ID: V-72303
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Remote X connections for interactive users must be encrypted. ###
# Open X displays allow an attacker to capture keystrokes and execute commands remotely.

######
#
# Check:
#
# Verify remote X connections for interactive users are encrypted.# # Check that remote X connections are encrypted with the following command:# # # grep -i x11forwarding /etc/ssh/sshd_config# X11Fowarding yes# # If the "X11Forwarding" keyword is set to "no", is missing, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure SSH to encrypt connections for interactive users.# # Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11Forwarding" keyword and set its value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):# # X11Fowarding yes# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040710' do
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
