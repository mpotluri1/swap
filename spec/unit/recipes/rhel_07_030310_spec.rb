#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030310
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000342-GPOS-00133 ####
#
# STIG ID: RHEL-07-030310
#
# Rule ID: SV-86709r1_rule
#
# Vuln ID: V-72085
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001851# The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.# NIST SP 800-53 Revision 4 :: AU-4 (1)# ######

### The operating system must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited. ###
# Information stored in one location is vulnerable to accidental or incidental deletion or alteration.# # Off-loading is a common process in information systems with limited audit storage capacity.# # Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224

######
#
# Check:
#
# Verify the operating system encrypts audit records off-loaded onto a different system or media from the system being audited.# # To determine if the transfer is encrypted, use the following command:# # # grep -i enable_krb5 /etc/audisp/audisp-remote.conf# enable_krb5 = yes# # If the value of the "enable_krb5" option is not set to "yes" or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.# # If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to encrypt the transfer of off-loaded audit records onto a different system or media from the system being audited.# # Uncomment the "enable_krb5" option in "/etc/audisp/audisp-remote.conf" and set it with the following line:# # enable_krb5 = yes#
#
######

require 'spec_helper'

describe '::rhel_07_030310' do
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
