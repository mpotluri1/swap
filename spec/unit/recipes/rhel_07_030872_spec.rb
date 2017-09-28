#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030872
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000004-GPOS-00004 ####
#
# STIG ID: RHEL-07-030872
#
# Rule ID: SV-87819r2_rule
#
# Vuln ID: V-73167
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000018# The information system automatically audits account creation actions.# NIST SP 800-53 :: AC-2 (4)# NIST SP 800-53A :: AC-2 (4).1 (i&ii)# NIST SP 800-53 Revision 4 :: AC-2 (4)# # CCI-000172# The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.# NIST SP 800-53 :: AU-12 c# NIST SP 800-53A :: AU-12.1 (iv)# NIST SP 800-53 Revision 4 :: AU-12 c# # CCI-001403# The information system automatically audits account modification actions.# NIST SP 800-53 :: AC-2 (4)# NIST SP 800-53A :: AC-2 (4).1 (i&ii)# NIST SP 800-53 Revision 4 :: AC-2 (4)# # CCI-002130# The information system automatically audits account enabling actions.# NIST SP 800-53 Revision 4 :: AC-2 (4)# ######

### The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow. ###
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.# # Audit records can be generated from various components within the information system (e.g., module or policy filter).

######
#
# Check:
#
# Verify the operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".# # Check the auditing rules in "/etc/audit/audit.rules" with the following command:# # # grep /etc/gshadow /etc/audit/audit.rules# # -w /etc/gshadow -p wa -k audit_rules_usergroup_modification# # If the command does not return a line, or the line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".# # Add or update the following rule in "/etc/audit/rules.d/audit.rules":# # -w /etc/gshadow -p wa -k identity# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030872' do
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
