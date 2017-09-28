#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000038-GPOS-00016 ####
#
# STIG ID: RHEL-07-030000
#
# Rule ID: SV-86703r1_rule
#
# Vuln ID: V-72079
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000126# The organization determines that the organization-defined subset of the auditable events defined in AU-2 are to be audited within the information system.# NIST SP 800-53 :: AU-2 d# NIST SP 800-53A :: AU-2.1 (v)# NIST SP 800-53 Revision 4 :: AU-2 d# # CCI-000131# The information system generates audit records containing information that establishes when an event occurred.# NIST SP 800-53 :: AU-3# NIST SP 800-53A :: AU-3.1# NIST SP 800-53 Revision 4 :: AU-3# ######

### Auditing must be configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events.
# These audit records must also identify individual identities of group account users. ###
# Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.# # Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.# # Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.# # Satisfies: SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000042-GPOS-00021, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096

######
#
# Check:
#
# Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.# # Check to see if auditing is active by issuing the following command:# # # systemctl is-active auditd.service# Active: active (running) since Tue 2015-01-27 19:41:23 EST; 22h ago# # If the "auditd" status is not active, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to produce audit records containing information to establish when (date and time) the events occurred.# # Enable the auditd service with the following command:# # # chkconfig auditd on#
#
######

require 'spec_helper'

describe '::rhel_07_030000' do
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
