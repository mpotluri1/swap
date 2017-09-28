#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040670
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040670
#
# Rule ID: SV-86919r1_rule
#
# Vuln ID: V-72295
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Network interfaces must not be in promiscuous mode. ###
# Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.# # If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to only authorized personnel.

######
#
# Check:
#
# Verify network interfaces are not in promiscuous mode unless approved by the ISSO and documented.# # Check for the status with the following command:# # # ip link | grep -i promisc# # If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.#
#
######
#
# Fix:
#
# Configure network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.# # Set the promiscuous mode of an interface to off with the following command:# # #ip link set dev <devicename> multicast off promisc off#
#
######

require 'spec_helper'

describe '::rhel_07_040670' do
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
