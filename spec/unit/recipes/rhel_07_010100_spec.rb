#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010100
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000029-GPOS-00010 ####
#
# STIG ID: RHEL-07-010100
#
# Rule ID: SV-86523r1_rule
#
# Vuln ID: V-71899
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000057# The information system initiates a session lock after the organization-defined time period of inactivity.# NIST SP 800-53 :: AC-11 a# NIST SP 800-53A :: AC-11.1 (ii)# NIST SP 800-53 Revision 4 :: AC-11 a# ######

### The operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces. ###
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.# # The session lock is implemented at the point where session activity can be determined and/or controlled.

######
#
# Check:
#
# Verify the operating system initiates a session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.# # If it is installed, GNOME must be configured to enforce a session lock after a 15-minute delay. Check for the session lock settings with the following commands:# # # grep -i  idle_activation_enabled /etc/dconf/db/local.d/*# [org/gnome/desktop/screensaver]   idle-activation-enabled=true# # If "idle-activation-enabled" is not set to "true", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to initiate a session lock after a 15-minute period of inactivity for graphical user interfaces.# # Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:# # # touch /etc/dconf/db/local.d/00-screensaver# # Add the setting to enable screensaver locking after 15 minutes of inactivity:# # [org/gnome/desktop/screensaver]# # idle-activation-enabled=true#
#
######

require 'spec_helper'

describe '::rhel_07_010100' do
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
