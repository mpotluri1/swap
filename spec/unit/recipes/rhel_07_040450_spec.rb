#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040450
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040450
#
# Rule ID: SV-86887r2_rule
#
# Vuln ID: V-72263
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The SSH daemon must perform strict mode checking of home directory configuration files. ###
# If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.

######
#
# Check:
#
# Verify the SSH daemon performs strict mode checking of home directory configuration files.# # The location of the "sshd_config" file may vary if a different daemon is in use.# # Inspect the "sshd_config" file with the following command:# # # grep -i strictmodes /etc/ssh/sshd_config# # StrictModes yes# # If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "yes":# # StrictModes yes# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040450' do
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
