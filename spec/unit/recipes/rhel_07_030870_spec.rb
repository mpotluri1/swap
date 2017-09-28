#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030870
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000004-GPOS-00004 ####
#
# STIG ID: RHEL-07-030870
#
# Rule ID: SV-86821r3_rule
#
# Vuln ID: V-72197
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000018# The information system automatically audits account creation actions.# NIST SP 800-53 :: AC-2 (4)# NIST SP 800-53A :: AC-2 (4).1 (i&ii)# NIST SP 800-53 Revision 4 :: AC-2 (4)# # CCI-000172# The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.# NIST SP 800-53 :: AU-12 c# NIST SP 800-53A :: AU-12.1 (iv)# NIST SP 800-53 Revision 4 :: AU-12 c# # CCI-001403# The information system automatically audits account modification actions.# NIST SP 800-53 :: AC-2 (4)# NIST SP 800-53A :: AC-2 (4).1 (i&ii)# NIST SP 800-53 Revision 4 :: AC-2 (4)# # CCI-002130# The information system automatically audits account enabling actions.# NIST SP 800-53 Revision 4 :: AC-2 (4)# ######

### The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd. ###
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.# # Audit records can be generated from various components within the information system (e.g., module or policy filter).# # Satisfies: SRG-OS-000004-GPOS-00004, SRG-OS-000239-GPOS-00089, SRG-OS-000240-GPOS-00090, SRG-OS-000241-GPOS-00091, SRG-OS-000303-GPOS-00120, SRG-OS-000476-GPOS-00221

######
#
# Check:
#
# Verify the operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd".# # Check the auditing rules in "/etc/audit/audit.rules" with the following command:# # # grep /etc/passwd /etc/audit/audit.rules# # -w /etc/passwd -p wa -k audit_rules_usergroup_modification# # If the command does not return a line, or the line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd".# # Add or update the following rule "/etc/audit/rules.d/audit.rules":# # -w /etc/passwd -p wa -k identity# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030870' do
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
