#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040520
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040520
#
# Rule ID: SV-86897r1_rule
#
# Vuln ID: V-72273
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The operating system must enable an application firewall, if available. ###
# Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.# # Satisfies: SRG-OS-000480-GPOS-00227, SRG-OS-000480-GPOS-00231, SRG-OS-000480-GPOS-00232

######
#
# Check:
#
# Verify the operating system enabled an application firewall.# # Check to see if "firewalld" is installed with the following command:# # # yum list installed firewalld# firewalld-0.3.9-11.el7.noarch.rpm# # If the "firewalld" package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed.# # If an application firewall is not installed, this is a finding.# # Check to see if the firewall is loaded and active with the following command:# # # systemctl status firewalld# firewalld.service - firewalld - dynamic firewall daemon# # Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)# Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago# # If "firewalld" does not show a status of "loaded" and "active", this is a finding.# # Check the state of the firewall:# # # firewall-cmd --state# running# # If "firewalld" does not show a state of "running", this is a finding.#
#
######
#
# Fix:
#
# Ensure the operating system's application firewall is enabled.# # Install the "firewalld" package, if it is not on the system, with the following command:# # # yum install firewalld# # Start the firewall via "systemctl" with the following command:# # # systemctl start firewalld#
#
######

require 'spec_helper'

describe '::rhel_07_040520' do
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
