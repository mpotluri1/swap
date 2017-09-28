#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040610
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040610
#
# Rule ID: SV-86907r1_rule
#
# Vuln ID: V-72283
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not forward Internet Protocol version 4 (IPv4) source-routed packets. ###
# Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.

######
#
# Check:
#
# Verify the system does not accept IPv4 source-routed packets.# # Check the value of the accept source route variable with the following command:# # # /sbin/sysctl -a | grep  net.ipv4.conf.all.accept_source_route# net.ipv4.conf.all.accept_source_route=0# # If the returned line does not have a value of "0", a line is not returned, or the returned line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" (or modify the line to have the required value):# # net.ipv4.conf.all.accept_source_route = 0#
#
######

require 'spec_helper'

describe '::rhel_07_040610' do
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
