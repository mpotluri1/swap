#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030750
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000042-GPOS-00020 ####
#
# STIG ID: RHEL-07-030750
#
# Rule ID: SV-86797r3_rule
#
# Vuln ID: V-72173
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000135# The information system generates audit records containing the organization-defined additional, more detailed information that is to be included in the audit records.# NIST SP 800-53 :: AU-3 (1)# NIST SP 800-53A :: AU-3 (1).1 (ii)# NIST SP 800-53 Revision 4 :: AU-3 (1)# # CCI-002884# The organization audits nonlocal maintenance and diagnostic sessions' organization-defined audit events.# NIST SP 800-53 Revision 4 :: MA-4 (1) (a)# ######

### All uses of the umount command must be audited. ###
# Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.# # At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.# # Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172

######
#
# Check:
#
# Verify the operating system generates audit records when successful/unsuccessful attempts to use the "umount" command occur.# # Check for the following system calls being audited by performing the following series of commands to check the file system rules in "/etc/audit/audit.rules":# # # grep -i /bin/umount /etc/audit/audit.rules# # -a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount# # If the command does not return any output, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "umount" command occur.# # Add or update the following rule in "/etc/audit/rules.d/audit.rules":# # -a always,exit -F path=/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-mount# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030750' do
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
