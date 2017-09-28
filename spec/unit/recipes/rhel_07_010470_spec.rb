#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010470
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00229 ####
#
# STIG ID: RHEL-07-010470
#
# Rule ID: SV-86583r2_rule
#
# Vuln ID: V-71959
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The operating system must not allow a non-certificate trusted host SSH logon to the system. ###
# Failure to restrict system access to authenticated users negatively impacts operating system security.

######
#
# Check:
#
# Verify the operating system does not allow a non-certificate trusted host SSH logon to the system.# # Check for the value of the "HostbasedAuthentication" keyword with the following command:# # # grep -i hostbasedauthentication /etc/ssh/sshd_config# HostbasedAuthentication no# # If the "HostbasedAuthentication" keyword is not set to "no", is missing, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to not allow a non-certificate trusted host SSH logon to the system.# # Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for "HostbasedAuthentication" keyword and set the value to "no":# # HostbasedAuthentication no# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_010470' do
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
