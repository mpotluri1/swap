#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020210
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000445-GPOS-00199 ####
#
# STIG ID: RHEL-07-020210
#
# Rule ID: SV-86613r2_rule
#
# Vuln ID: V-71989
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002165# The information system enforces organization-defined discretionary access control policies over defined subjects and objects.# NIST SP 800-53 Revision 4 :: AC-3 (4)# # CCI-002696# The information system verifies correct operation of organization-defined security functions.# NIST SP 800-53 Revision 4 :: SI-6 a# ######

### The operating system must enable SELinux. ###
# Without verification of the security functions, security functions may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.# # This requirement applies to operating systems performing security function verification/testing and/or systems and environments that require this functionality.

######
#
# Check:
#
# Verify the operating system verifies correct operation of all security functions.# # Check if "SELinux" is active and in "Enforcing" mode with the following command:# # # getenforce# Enforcing# # If "SELinux" is not active and not in "Enforcing" mode, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to verify correct operation of all security functions.# # Set the "SELinux" status and the "Enforcing" mode by modifying the "/etc/selinux/config" file to have the following line:# # SELINUX=enforcing# # A reboot is required for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_020210' do
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
