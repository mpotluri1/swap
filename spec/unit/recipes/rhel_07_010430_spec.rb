#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010430
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00226 ####
#
# STIG ID: RHEL-07-010430
#
# Rule ID: SV-86575r1_rule
#
# Vuln ID: V-71951
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The delay between logon prompts following a failed console logon attempt must be at least four seconds. ###
# Configuring the operating system to implement organization-wide security implementation guides and security checklists verifies compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.# # Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example, registry settings; account, file, and directory permission settings; and settings for functions, ports, protocols, services, and remote connections.

######
#
# Check:
#
# Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt.# # Check the value of the "fail_delay" parameter in the "/etc/login.defs" file with the following command:# # # grep -i fail_delay /etc/login.defs# FAIL_DELAY 4# # If the value of "FAIL_DELAY" is not set to "4" or greater, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.# # Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:# # FAIL_DELAY 4#
#
######

require 'spec_helper'

describe '::rhel_07_010430' do
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
