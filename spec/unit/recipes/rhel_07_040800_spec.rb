#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040800
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040800
#
# Rule ID: SV-86937r1_rule
#
# Vuln ID: V-72313
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### SNMP community strings must be changed from the default. ###
# Whether active or not, default Simple Network Management Protocol (SNMP) community strings must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network and use the information to potentially compromise the integrity of the system or network(s). It is highly recommended that SNMP version 3 user authentication and message encryption be used in place of the version 2 community strings.

######
#
# Check:
#
# Verify that a system using SNMP is not using default community strings.# # Check to see if the "/etc/snmp/snmpd.conf" file exists with the following command:# # # ls -al /etc/snmp/snmpd.conf# -rw-------   1 root root      52640 Mar 12 11:08 snmpd.conf# # If the file does not exist, this is Not Applicable.# # If the file does exist, check for the default community strings with the following commands:# # # grep public /etc/snmp/snmpd.conf# # grep private /etc/snmp/snmpd.conf# # If either of these commands returns any output, this is a finding.#
#
######
#
# Fix:
#
# If the "/etc/snmp/snmpd.conf" file exists, modify any lines that contain a community string value of "public" or "private" to another string value.#
#
######

require 'spec_helper'

describe '::rhel_07_040800' do
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
