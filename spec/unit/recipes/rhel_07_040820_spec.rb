#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040820
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040820
#
# Rule ID: SV-86941r1_rule
#
# Vuln ID: V-72317
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not have unauthorized IP tunnels configured. ###
# IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).

######
#
# Check:
#
# Verify the system does not have unauthorized IP tunnels configured.# # Check to see if "libreswan" is installed with the following command:# # # yum list installed libreswan# openswan-2.6.32-27.el6.x86_64# # If "libreswan" is installed, check to see if the "IPsec" service is active with the following command:# # # systemctl status ipsec# ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec# Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)# Active: inactive (dead)# # If the "IPsec" service is active, check to see if any tunnels are configured in "/etc/ipsec.conf" and "/etc/ipsec.d/" with the following commands:# # # grep -i conn /etc/ipsec.conf# conn mytunnel# # # grep -i conn /etc/ipsec.d/*.conf# conn mytunnel# # If there are indications that a "conn" parameter is configured for a tunnel, ask the System Administrator if the tunnel is documented with the ISSO. If "libreswan" is installed, "IPsec" is active, and an undocumented tunnel is active, this is a finding.#
#
######
#
# Fix:
#
# Remove all unapproved tunnels from the system, or document them with the ISSO.#
#
######

require 'spec_helper'

describe '::rhel_07_040820' do
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
