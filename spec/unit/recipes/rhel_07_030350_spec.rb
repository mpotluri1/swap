#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030350
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000343-GPOS-00134 ####
#
# STIG ID: RHEL-07-030350
#
# Rule ID: SV-86717r2_rule
#
# Vuln ID: V-72093
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001855# The information system provides a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity.# NIST SP 800-53 Revision 4 :: AU-5 (1)# ######

### The operating system must immediately notify the System Administrator (SA) and Information System Security Officer (ISSO) (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached. ###
# If security personnel are not notified immediately when the threshold for the repository maximum audit record storage capacity is reached, they are unable to expand the audit record storage capacity before records are lost.

######
#
# Check:
#
# Verify the operating system immediately notifies the SA and ISSO (at a minimum) via email when the threshold for the repository maximum audit record storage capacity is reached.# # Check what account the operating system emails when the threshold for the repository maximum audit record storage capacity is reached with the following command:# # # grep -i action_mail_acct  /etc/audit/auditd.conf# action_mail_acct = root# # If the value of the "action_mail_acct" keyword is not set to "root" and other accounts for security personnel, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to immediately notify the SA and ISSO (at a minimum) when the threshold for the repository maximum audit record storage capacity is reached.# # Uncomment or edit the "action_mail_acct" keyword in "/etc/audit/auditd.conf" and set it to root and any other accounts associated with security personnel.# # action_mail_acct = root#
#
######

require 'spec_helper'

describe '::rhel_07_030350' do
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
