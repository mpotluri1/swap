#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010300
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000106-GPOS-00053 ####
#
# STIG ID: RHEL-07-010300
#
# Rule ID: SV-86563r2_rule
#
# Vuln ID: V-71939
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000766# The information system implements multifactor authentication for network access to non-privileged accounts.# NIST SP 800-53 :: IA-2 (2)# NIST SP 800-53A :: IA-2 (2).1# NIST SP 800-53 Revision 4 :: IA-2 (2)# ######

### The SSH daemon must not allow authentication using an empty password. ###
# Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.

######
#
# Check:
#
# To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command:# # # grep -i PermitEmptyPasswords /etc/ssh/sshd_config# PermitEmptyPasswords no# # If no line, a commented line, or a line indicating the value "no" is returned, the required value is set.# # If the required value is not set, this is a finding.#
#
######
#
# Fix:
#
# To explicitly disallow remote logon from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config":# # PermitEmptyPasswords no# # The SSH service must be restarted for changes to take effect.  Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.#
#
######

require 'spec_helper'

describe '::rhel_07_010300' do
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
