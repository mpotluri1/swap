#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030580
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000392-GPOS-00172 ####
#
# STIG ID: RHEL-07-030580
#
# Rule ID: SV-86763r3_rule
#
# Vuln ID: V-72139
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000172# The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.# NIST SP 800-53 :: AU-12 c# NIST SP 800-53A :: AU-12.1 (iv)# NIST SP 800-53 Revision 4 :: AU-12 c# # CCI-002884# The organization audits nonlocal maintenance and diagnostic sessions' organization-defined audit events.# NIST SP 800-53 Revision 4 :: MA-4 (1) (a)# ######

### All uses of the chcon command must be audited. ###
# Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.# # Audit records can be generated from various components within the information system (e.g., module or policy filter).# # Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000463-GPOS-00207, SRG-OS-000465-GPOS-00209

######
#
# Check:
#
# Verify the operating system generates audit records when successful/unsuccessful attempts to use the "chcon" command occur.# # Check the file system rule in "/etc/audit/audit.rules" with the following command:# # # grep -i /usr/bin/chcon /etc/audit/audit.rules# # -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change# # If the command does not return any output, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to generate audit records when successful/unsuccessful attempts to use the "chcon" command occur.# # Add or update the following rule in "/etc/audit/rules.d/audit.rules":# # -a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030580' do
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
