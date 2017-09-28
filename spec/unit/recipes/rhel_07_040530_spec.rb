#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040530
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040530
#
# Rule ID: SV-86899r1_rule
#
# Vuln ID: V-72275
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must display the date and time of the last successful account logon upon logon. ###
# Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.

######
#
# Check:
#
# Verify users are provided with feedback on when account accesses last occurred.# # Check that "pam_lastlog" is used and not silent with the following command:# # # grep pam_lastlog /etc/pam.d/postlogin-ac# # session     required      pam_lastlog.so showfailed silent# # If "pam_lastlog" is missing from "/etc/pam.d/postlogin-ac" file, or the silent option is present on the line check for the "PrintLastLog" keyword in the sshd daemon configuration file, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/postlogin-ac".# # Add the following line to the top of "/etc/pam.d/postlogin-ac":# # session     required      pam_lastlog.so showfailed#
#
######

require 'spec_helper'

describe '::rhel_07_040530' do
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
