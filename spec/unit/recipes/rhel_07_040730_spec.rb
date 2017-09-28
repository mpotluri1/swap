#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040730
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040730
#
# Rule ID: SV-86931r2_rule
#
# Vuln ID: V-72307
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### An X Windows display manager must not be installed unless approved. ###
# Internet services that are not required for system or application processes must not be active to decrease the attack surface of the system. X Windows has a long history of security vulnerabilities and will not be used unless approved and documented.

######
#
# Check:
#
# Verify that if the system has X Windows System installed, it is authorized.# # Check for the X11 package with the following command:# # # yum group list installed "X Window System"# # Ask the System Administrator if use of the X Windows System is an operational requirement.# # If the use of X Windows on the system is not documented with the Information System Security Officer (ISSO), this is a finding.#
#
######
#
# Fix:
#
# Document the requirement for an X Windows server with the ISSO or remove the related packages with the following commands:# # #yum groupremove "X Window System"# # #yum remove xorg-x11-server-common#
#
######

require 'spec_helper'

describe '::rhel_07_040730' do
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
