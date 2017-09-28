#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010350
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000373-GPOS-00156 ####
#
# STIG ID: RHEL-07-010350
#
# Rule ID: SV-86573r2_rule
#
# Vuln ID: V-71949
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002038# The organization requires users to reauthenticate when organization-defined circumstances or situations requiring reauthentication.# NIST SP 800-53 Revision 4 :: IA-11# ######

### Users must re-authenticate for privilege escalation. ###
# Without re-authentication, users may access resources or perform tasks for which they do not have authorization.# # When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.# # Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158

######
#
# Check:
#
# Verify the operating system requires users to reauthenticate for privilege escalation.# # Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:# # # grep -i authenticate /etc/sudoers /etc/sudoers.d/*# # If any line is found with a "!authenticate" tag, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to require users to reauthenticate for privilege escalation.# # Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:# # Remove any occurrences of "!authenticate" tags in the file.#
#
######

require 'spec_helper'

describe '::rhel_07_010350' do
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
