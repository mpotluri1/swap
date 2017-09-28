#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010081
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000029-GPOS-00010 ####
#
# STIG ID: RHEL-07-010081
#
# Rule ID: SV-87807r2_rule
#
# Vuln ID: V-73155
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000057# The information system initiates a session lock after the organization-defined time period of inactivity.# NIST SP 800-53 :: AC-11 a# NIST SP 800-53A :: AC-11.1 (ii)# NIST SP 800-53 Revision 4 :: AC-11 a# ######

### The operating system must set the lock delay setting  for all connection types. ###
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.# # The session lock is implemented at the point where session activity can be determined and/or controlled.

######
#
# Check:
#
# Verify the operating system prevents a user from overriding a screensaver lock after a 15-minute period of inactivity for graphical user interfaces.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable. The screen program must be installed to lock sessions on the console.# # Determine which profile the system database is using with the following command:# # grep system-db /etc/dconf/profile/user# # system-db:local# # Check for the lock delay setting with the following command:# # Note: The example below is using the database "local" for the system, so the path is "/etc/dconf/db/local.d". This path must be modified if a database other than "local" is being used.# # # grep -i lock-delay /etc/dconf/db/local.d/locks/*# # /org/gnome/desktop/screensaver/lock-delay# # If the command does not return a result, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to prevent a user from overriding a screensaver lock after a 15-minute period of inactivity for graphical user interfaces.# # Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:# # Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.# # # touch /etc/dconf/db/local.d/locks/session# # Add the setting to lock the screensaver lock delay:# # /org/gnome/desktop/screensaver/lock-delay#
#
######

require 'spec_helper'

describe '::rhel_07_010081' do
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
