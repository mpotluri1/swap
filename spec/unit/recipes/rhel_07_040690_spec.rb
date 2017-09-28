#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040690
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040690
#
# Rule ID: SV-86923r1_rule
#
# Vuln ID: V-72299
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### A File Transfer Protocol (FTP) server package must not be installed unless needed. ###
# The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.

######
#
# Check:
#
# Verify a lightweight FTP server has not been installed on the system.# # Check to see if a lightweight FTP server has been installed with the following commands:# # # yum list installed lftpd# lftp-4.4.8-7.el7.x86_64.rpm# # If "lftpd" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.#
#
######
#
# Fix:
#
# Document the "lftpd" package with the ISSO as an operational requirement or remove it from the system with the following command:# # # yum remove lftpd#
#
######

require 'spec_helper'

describe '::rhel_07_040690' do
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
