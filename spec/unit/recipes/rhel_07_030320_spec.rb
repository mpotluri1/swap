#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030320
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000342-GPOS-00133 ####
#
# STIG ID: RHEL-07-030320
#
# Rule ID: SV-86711r2_rule
#
# Vuln ID: V-72087
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001851# The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.# NIST SP 800-53 Revision 4 :: AU-4 (1)# ######

### The audit system must take appropriate action when the audit storage volume is full. ###
# Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.

######
#
# Check:
#
# Verify the action the operating system takes if the disk the audit records are written to becomes full.# # To determine the action that takes place if the disk is full on the remote server, use the following command:# # # grep -i disk_full_action /etc/audisp/audisp-remote.conf# disk_full_action = single# # To determine the action that takes place if the network connection fails, use the following command:# # # grep -i network_failure_action /etc/audisp/audisp-remote.conf# network_failure_action = stop# # If the value of the "network_failure_action" option is not "syslog", "single", or "halt", or the line is commented out, this is a finding.# # If the value of the "disk_full_action" option is not "syslog", "single", or "halt", or the line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the action the operating system takes if the disk the audit records are written to becomes full.# # Uncomment or edit the "disk_full_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single", or "halt", such as the following line:# # disk_full_action = single# # Uncomment the "network_failure_action" option in "/etc/audisp/audisp-remote.conf" and set it to "syslog", "single", or "halt".#
#
######

require 'spec_helper'

describe '::rhel_07_030320' do
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
