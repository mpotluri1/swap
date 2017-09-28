#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_041010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000424-GPOS-00188 ####
#
# STIG ID: RHEL-07-041010
#
# Rule ID: SV-87829r1_rule
#
# Vuln ID: V-73177
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001443# The information system protects wireless access to the system using authentication of users and/or devices.# NIST SP 800-53 :: AC-18 (1)# NIST SP 800-53A :: AC-18 (1).1# NIST SP 800-53 Revision 4 :: AC-18 (1)# # CCI-001444# The information system protects wireless access to the system using encryption.# NIST SP 800-53 :: AC-18 (1)# NIST SP 800-53A :: AC-18 (1).1# NIST SP 800-53 Revision 4 :: AC-18 (1)# # CCI-002418# The information system protects the confidentiality and/or integrity of transmitted information.# NIST SP 800-53 Revision 4 :: SC-8# ######

### Wireless network adapters must be disabled. ###
# The use of wireless networking can introduce many different attack vectors into the organization's network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.

######
#
# Check:
#
# Verify that there are no wireless interfaces configured on the system.# # This is N/A for systems that do not have wireless network adapters.# # Check for the presence of active wireless interfaces with the following command:# # # nmcli device# DEVICE TYPE STATE# eth0 ethernet connected# wlp3s0 wifi disconnected# lo loopback unmanaged# # If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding.#
#
######
#
# Fix:
#
# Configure the system to disable all wireless network interfaces with the following command:# # #nmcli radio wifi off#
#
######

require 'spec_helper'

describe '::rhel_07_041010' do
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
