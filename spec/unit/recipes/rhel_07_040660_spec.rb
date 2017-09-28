#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040660
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040660
#
# Rule ID: SV-86917r2_rule
#
# Vuln ID: V-72293
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not send Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirects. ###
# ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages contain information from the system's route table, possibly revealing portions of the network topology.

######
#
# Check:
#
# Verify the system does not send IPv4 ICMP redirect messages.# # Check the value of the "all send_redirects" variables with the following command:# # # grep  'net.ipv4.conf.all.send_redirects' /etc/sysctl.conf# # net.ipv4.conf.all.send_redirects=0# # If the returned line does not have a value of "0", or a line is not returned, this is a finding.#
#
######
#
# Fix:
#
# Configure the system to not allow interfaces to perform IPv4 ICMP redirects.# # Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):# # net.ipv4.conf.all.send_redirects=0#
#
######

require 'spec_helper'

describe '::rhel_07_040660' do
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
