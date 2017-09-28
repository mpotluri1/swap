#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040350
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040350
#
# Rule ID: SV-86867r2_rule
#
# Vuln ID: V-72243
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The SSH daemon must not allow authentication using rhosts authentication. ###
# Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

######
#
# Check:
#
# Verify the SSH daemon does not allow authentication using known hosts authentication.# # To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command:# # # grep -i IgnoreRhosts /etc/ssh/sshd_config# # IgnoreRhosts yes# # If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.#
#
######
#
# Fix:
#
# Configure the SSH daemon to not allow authentication using known hosts authentication.# # Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":# # IgnoreRhosts yes#
#
######

require 'spec_helper'

describe '::rhel_07_040350' do
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
