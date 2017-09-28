#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040420
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040420
#
# Rule ID: SV-86881r1_rule
#
# Vuln ID: V-72257
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The SSH private host key files must have mode 0600 or less permissive. ###
# If an unauthorized user obtains the private SSH host key file, the host could be impersonated.

######
#
# Check:
#
# Verify the SSH private host key files have mode "0600" or less permissive.# # The following command will find all SSH private key files on the system:# # # find / -name '*ssh_host*key'# # Check the mode of the private host key files under "/etc/ssh" file with the following command:# # # ls -lL /etc/ssh/*key# -rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key# -rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key# -rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key# # If any file has a mode more permissive than "0600", this is a finding.#
#
######
#
# Fix:
#
# Configure the mode of SSH private host key files under "/etc/ssh" to "0600" with the following command:# # # chmod 0600 /etc/ssh/ssh_host*key#
#
######

require 'spec_helper'

describe '::rhel_07_040420' do
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
