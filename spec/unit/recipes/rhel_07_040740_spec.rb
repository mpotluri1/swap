#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040740
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040740
#
# Rule ID: SV-86933r1_rule
#
# Vuln ID: V-72309
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not be performing packet forwarding unless the system is a router. ###
# Routing protocol daemons are typically used on routers to exchange network topology information with other routers. If this software is used when not required, system network information may be unnecessarily transmitted across the network.

######
#
# Check:
#
# Verify the system is not performing packet forwarding, unless the system is a router.# # Check to see if IP forwarding is enabled using the following command:# # # /sbin/sysctl -a | grep  net.ipv4.ip_forward# net.ipv4.ip_forward=0# # If IP forwarding value is "1" and the system is hosting any application, database, or web servers, this is a finding.#
#
######
#
# Fix:
#
# Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):# # net.ipv4.ip_forward = 0#
#
######

require 'spec_helper'

describe '::rhel_07_040740' do
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
