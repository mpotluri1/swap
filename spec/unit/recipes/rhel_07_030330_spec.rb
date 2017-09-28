#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030330
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000343-GPOS-00134 ####
#
# STIG ID: RHEL-07-030330
#
# Rule ID: SV-86713r1_rule
#
# Vuln ID: V-72089
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001855# The information system provides a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity.# NIST SP 800-53 Revision 4 :: AU-5 (1)# ######

### The operating system must immediately notify the System Administrator (SA) and Information System Security Officer ISSO (at a minimum) when allocated audit record storage volume reaches 75% of the repository maximum audit record storage capacity. ###
# If security personnel are not notified immediately when storage volume reaches 75 percent utilization, they are unable to plan for audit record storage capacity expansion.

######
#
# Check:
#
# Verify the operating system immediately notifies the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.# # Check the system configuration to determine the partition the audit records are being written to with the following command:# # # grep log_file /etc/audit/auditd.conf# log_file = /var/log/audit/audit.log# # Check the size of the partition that audit records are written to (with the example being "/var/log/audit/"):# # # df -h /var/log/audit/# 0.9G /var/log/audit# # If the audit records are not being written to a partition specifically created for audit records (in this example "/var/log/audit" is a separate partition), determine the amount of space other files in the partition are currently occupying with the following command:# # # du -sh <partition># 1.8G /var# # Determine what the threshold is for the system to take action when 75 percent of the repository maximum audit record storage capacity is reached:# # # grep -i space_left /etc/audit/auditd.conf# space_left = 225# # If the value of the "space_left" keyword is not set to 25 percent of the total partition size, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to immediately notify the SA and ISSO (at a minimum) when allocated audit record storage volume reaches 75 percent of the repository maximum audit record storage capacity.# # Check the system configuration to determine the partition the audit records are being written to:# # # grep log_file /etc/audit/auditd.conf# # Determine the size of the partition that audit records are written to (with the example being "/var/log/audit/"):# # # df -h /var/log/audit/# # Set the value of the "space_left" keyword in "/etc/audit/auditd.conf" to 75 percent of the partition size.#
#
######

require 'spec_helper'

describe '::rhel_07_030330' do
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
