#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030530
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000064-GPOS-00033 ####
#
# STIG ID: RHEL-07-030530
#
# Rule ID: SV-86753r2_rule
#
# Vuln ID: V-72129
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000172# The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.# NIST SP 800-53 :: AU-12 c# NIST SP 800-53A :: AU-12.1 (iv)# NIST SP 800-53 Revision 4 :: AU-12 c# # CCI-002884# The organization audits nonlocal maintenance and diagnostic sessions' organization-defined audit events.# NIST SP 800-53 Revision 4 :: MA-4 (1) (a)# ######

### All uses of the open_by_handle_at command must be audited. ###
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.# # Audit records can be generated from various components within the information system (e.g., module or policy filter).# # Satisfies: SRG-OS-000064-GPOS-00033, SRG-OS-000458-GPOS-00203, SRG-OS-000461-GPOS-00205, SRG-OS-000392-GPOS-00172

######
#
# Check:
#
# Verify the operating system generates audit records when successful/unsuccessful attempts to use the "open_by_handle_at" command occur.# # Check the file system rules in "/etc/audit/audit.rules" with the following commands:# # Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the lines appropriate for the system architecture must be present.# # # grep -i open_by_handle_at /etc/audit/audit.rules# # -a always,exit -F arch=b32 -S open_by_handle_at -Fexit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access# # -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access# # If the command does not return any output, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "open_by_handle_at" command occur.# # Add or update the following rule in "/etc/audit/rules.d/audit.rules" (removing those that do not match the CPU architecture):# # -a always,exit -F arch=b32 -S open_by_handle_at -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access# # -a always,exit -F arch=b64 -S open_by_handle_at -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030530' do
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
