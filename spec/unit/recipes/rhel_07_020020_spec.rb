#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020020
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000324-GPOS-00125 ####
#
# STIG ID: RHEL-07-020020
#
# Rule ID: SV-86595r1_rule
#
# Vuln ID: V-71971
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002165# The information system enforces organization-defined discretionary access control policies over defined subjects and objects.# NIST SP 800-53 Revision 4 :: AC-3 (4)# # CCI-002235# The information system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.# NIST SP 800-53 Revision 4 :: AC-6 (10)# ######

### The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures. ###
# Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.# # Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

######
#
# Check:
#
# Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.# # Get a list of authorized users (other than System Administrator and guest accounts) for the system.# # Check the list against the system by using the following command:# # # semanage login -l | more# Login Name  SELinux User   MLS/MCS Range  Service# __default__  user_u    s0-s0:c0.c1023   *# root   unconfined_u   s0-s0:c0.c1023   *# system_u  system_u   s0-s0:c0.c1023   *# joe  staff_u   s0-s0:c0.c1023   *# # All administrators must be mapped to the "sysadm_u" or "staff_u" users with the appropriate domains (sysadm_t and staff_t).# # All authorized non-administrative users must be mapped to the "user_u" role or the appropriate domain (user_t).# # If they are not mapped in this way, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.# # Use the following command to map a new user to the "sysdam_u" role:# # #semanage login -a -s sysadm_u <username># # Use the following command to map an existing user to the "sysdam_u" role:# # #semanage login -m -s sysadm_u <username># # Use the following command to map a new user to the "staff_u" role:# # #semanage login -a -s staff_u <username># # Use the following command to map an existing user to the "staff_u" role:# # #semanage login -m -s staff_u <username># # Use the following command to map a new user to the "user_u" role:# # # semanage login -a -s user_u <username># # Use the following command to map an existing user to the "user_u" role:# # # semanage login -m -s user_u <username>#
#
######

require 'spec_helper'

describe '::rhel_07_020020' do
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
