#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021040
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021040
#
# Rule ID: SV-86673r1_rule
#
# Vuln ID: V-72049
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### The umask must be set to 077 for all local interactive user accounts. ###
# The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be "0". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.

######
#
# Check:
#
# Verify that the default umask for all local interactive users is "077".# # Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.# # Check all local interactive user initialization files for interactive users with the following command:# # Note: The example is for a system that is configured to create users home directories in the "/home" directory.# # # grep -i umask /home/*/.*# # If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.#
#
######
#
# Fix:
#
# Remove the umask statement from all local interactive users’ initialization files.# # If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the Information System Security Officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account’s environment variables.#
#
######

require 'spec_helper'

describe '::rhel_07_021040' do
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
