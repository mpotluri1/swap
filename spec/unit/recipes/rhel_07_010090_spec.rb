#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010090
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000029-GPOS-00010 ####
#
# STIG ID: RHEL-07-010090
#
# Rule ID: SV-86521r1_rule
#
# Vuln ID: V-71897
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000057# The information system initiates a session lock after the organization-defined time period of inactivity.# NIST SP 800-53 :: AC-11 a# NIST SP 800-53A :: AC-11.1 (ii)# NIST SP 800-53 Revision 4 :: AC-11 a# ######

### The operating system must have the screen package installed. ###
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.# # The screen package allows for a session lock to be implemented and configured.

######
#
# Check:
#
# Verify the operating system has the screen package installed.# # Check to see if the screen package is installed with the following command:# # # yum list installed | grep screen# screen-4.3.1-3-x86_64.rpm# # If is not installed, this is a finding.#
#
######
#
# Fix:
#
# Install the screen package to allow the initiation a session lock after a 15-minute period of inactivity for graphical users interfaces.# # Install the screen program (if it is not on the system) with the following command:# # # yum install screen# # The console can now be locked with the following key combination:# # ctrl+A x#
#
######

require 'spec_helper'

describe '::rhel_07_010090' do
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
