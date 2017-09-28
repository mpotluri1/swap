#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030300
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000342-GPOS-00133 ####
#
# STIG ID: RHEL-07-030300
#
# Rule ID: SV-86707r1_rule
#
# Vuln ID: V-72083
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001851# The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.# NIST SP 800-53 Revision 4 :: AU-4 (1)# ######

### The operating system must off-load audit records onto a different system or media from the system being audited. ###
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.# # Off-loading is a common process in information systems with limited audit storage capacity.# # Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

######
#
# Check:
#
# Verify the operating system off-loads audit records onto a different system or media from the system being audited.# # To determine the remote server that the records are being sent to, use the following command:# # # grep -i remote_server /etc/audisp/audisp-remote.conf# remote_server = 10.0.21.1# # If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.# # If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to off-load audit records onto a different system or media from the system being audited.# # Set the remote server option in "/etc/audisp/audisp-remote.conf" with the IP address of the log aggregation server.#
#
######

require 'spec_helper'

describe '::rhel_07_030300' do
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
