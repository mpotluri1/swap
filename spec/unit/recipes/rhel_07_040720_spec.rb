#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040720
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040720
#
# Rule ID: SV-86929r1_rule
#
# Vuln ID: V-72305
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode. ###
# Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.

######
#
# Check:
#
# Verify the TFTP daemon is configured to operate in secure mode.# # Check to see if a TFTP server has been installed with the following commands:# # # yum list installed | grep tftp# tftp-0.49-9.el7.x86_64.rpm# # If a TFTP server is not installed, this is Not Applicable.# # If a TFTP server is installed, check for the server arguments with the following command:# # # grep server_arge /etc/xinetd.d/tftp# server_args = -s /var/lib/tftpboot# # If the "server_args" line does not have a "-s" option and a subdirectory is not assigned, this is a finding.#
#
######
#
# Fix:
#
# Configure the TFTP daemon to operate in secure mode by adding the following line to "/etc/xinetd.d/tftp" (or modify the line to have the required value):# # server_args = -s /var/lib/tftpboot#
#
######

require 'spec_helper'

describe '::rhel_07_040720' do
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
