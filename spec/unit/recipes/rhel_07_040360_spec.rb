#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040360
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040360
#
# Rule ID: SV-86869r2_rule
#
# Vuln ID: V-72245
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must display the date and time of the last successful account logon upon an SSH logon. ###
# Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.

######
#
# Check:
#
# Verify SSH provides users with feedback on when account accesses last occurred.# # Check that "PrintLastLog" keyword in the sshd daemon configuration file is used and set to "yes" with the following command:# # # grep -i printlastlog /etc/ssh/sshd_config# PrintLastLog yes# # If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/sshd" or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config" will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).# # Add the following line to the top of "/etc/pam.d/sshd":# # session     required      pam_lastlog.so showfailed# # Or modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the following:# # PrintLastLog yes# # The SSH service must be restarted for changes to "sshd_config" to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040360' do
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
