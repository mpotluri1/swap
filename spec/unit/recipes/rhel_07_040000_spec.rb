#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000027-GPOS-00008 ####
#
# STIG ID: RHEL-07-040000
#
# Rule ID: SV-86841r1_rule
#
# Vuln ID: V-72217
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000054# The information system limits the number of concurrent sessions for each organization-defined account and/or account type to an organization-defined number of sessions.# NIST SP 800-53 :: AC-10# NIST SP 800-53A :: AC-10.1 (ii)# NIST SP 800-53 Revision 4 :: AC-10# ######

### The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types. ###
# Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.# # This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.

######
#
# Check:
#
# Verify the operating system limits the number of concurrent sessions to "10" for all accounts and/or account types by issuing the following command:# # # grep "maxlogins" /etc/security/limits.conf# * hard maxlogins 10# # This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.# # If the "maxlogins" item is missing or the value is not set to "10" or less for all domains that have the "maxlogins" item assigned, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to limit the number of concurrent sessions to "10" for all accounts and/or account types.# # Add the following line to the top of the /etc/security/limits.conf:# # * hard maxlogins 10#
#
######

require 'spec_helper'

describe '::rhel_07_040000' do
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
