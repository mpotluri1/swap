#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010500
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000104-GPOS-00051 ####
#
# STIG ID: RHEL-07-010500
#
# Rule ID: SV-86589r1_rule
#
# Vuln ID: V-71965
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000766# The information system implements multifactor authentication for network access to non-privileged accounts.# NIST SP 800-53 :: IA-2 (2)# NIST SP 800-53A :: IA-2 (2).1# NIST SP 800-53 Revision 4 :: IA-2 (2)# ######

### The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication. ###
# To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.# # Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:# # 1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication;# # and# # 2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.# # Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055, SRG-OS-000108-GPOS-00057, SRG-OS-000108-GPOS-00058

######
#
# Check:
#
# Verify the operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication.# # Check to see if smartcard authentication is enforced on the system:# # # authconfig --test | grep -i smartcard# # The entry for use only smartcard for logon may be enabled, and the smartcard module and smartcard removal actions must not be blank.# # If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to require individuals to be authenticated with a multifactor authenticator.# # Enable smartcard logons with the following commands:# # # authconfig --enablesmartcard --smartcardaction=1 --update# # authconfig --enablerequiresmartcard -update# # Modify the "/etc/pam_pkcs11/pkcs11_eventmgr.conf" file to uncomment the following line:# # #/usr/X11R6/bin/xscreensaver-command -lock# # Modify the "/etc/pam_pkcs11/pam_pkcs11.conf" file to use the cackey module if required.#
#
######

require 'spec_helper'

describe '::rhel_07_010500' do
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
