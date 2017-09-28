#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040600
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040600
#
# Rule ID: SV-86905r1_rule
#
# Vuln ID: V-72281
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### For systems using DNS resolution, at least two name servers must be configured. ###
# To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.

######
#
# Check:
#
# Determine whether the system is using local or DNS name resolution with the following command:# # # grep hosts /etc/nsswitch.conf# hosts:   files dns# # If the DNS entry is missing from the host’s line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty.# # Verify the "/etc/resolv.conf" file is empty with the following command:# # # ls -al /etc/resolv.conf# -rw-r--r--  1 root root        0 Aug 19 08:31 resolv.conf# # If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding.# # If the DNS entry is found on the host’s line of the "/etc/nsswitch.conf" file, verify the operating system is configured to use two or more name servers for DNS resolution.# # Determine the name servers used by the system with the following command:# # # grep nameserver /etc/resolv.conf# nameserver 192.168.1.2# nameserver 192.168.1.3# # If less than two lines are returned that are not commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to use two or more name servers for DNS resolution.# # Edit the "/etc/resolv.conf" file to uncomment or add the two or more "nameserver" option lines with the IP address of local authoritative name servers. If local host resolution is being performed, the "/etc/resolv.conf" file must be empty. An empty "/etc/resolv.conf" file can be created as follows:# # # echo -n > /etc/resolv.conf# # And then make the file immutable with the following command:# # # chattr +i /etc/resolv.conf# # If the "/etc/resolv.conf" file must be mutable, the required configuration must be documented with the Information System Security Officer (ISSO) and the file must be verified by the system file integrity tool.#
#
######

require 'spec_helper'

describe '::rhel_07_040600' do
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
