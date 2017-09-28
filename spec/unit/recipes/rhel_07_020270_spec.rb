#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020270
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020270
#
# Rule ID: SV-86625r1_rule
#
# Vuln ID: V-72001
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The system must not have unnecessary accounts. ###
# Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.

######
#
# Check:
#
# Verify all accounts on the system are assigned to an active system, application, or user account.# # Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).# # Check the system accounts on the system with the following command:# # # more /etc/passwd# root:x:0:0:root:/root:/bin/bash# bin:x:1:1:bin:/bin:/sbin/nologin# daemon:x:2:2:daemon:/sbin:/sbin/nologin# sync:x:5:0:sync:/sbin:/bin/sync# shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown# halt:x:7:0:halt:/sbin:/sbin/halt# games:x:12:100:games:/usr/games:/sbin/nologin# gopher:x:13:30:gopher:/var/gopher:/sbin/nologin# # Accounts such as "games" and "gopher" are not authorized accounts as they do not support authorized system functions.# # If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding.#
#
######
#
# Fix:
#
# Configure the system so all accounts on the system are assigned to an active system, application, or user account.# # Remove accounts that do not support approved system activities or that allow for a normal user to perform administrative-level actions.# # Document all authorized accounts on the system.#
#
######

require 'spec_helper'

describe '::rhel_07_020270' do
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
