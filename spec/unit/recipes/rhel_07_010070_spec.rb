#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010070
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000029-GPOS-00010 ####
#
# STIG ID: RHEL-07-010070
#
# Rule ID: SV-86517r2_rule
#
# Vuln ID: V-71893
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000057# The information system initiates a session lock after the organization-defined time period of inactivity.# NIST SP 800-53 :: AC-11 a# NIST SP 800-53A :: AC-11.1 (ii)# NIST SP 800-53 Revision 4 :: AC-11 a# ######

### The operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces. ###
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.# # The session lock is implemented at the point where session activity can be determined and/or controlled.

######
#
# Check:
#
# Verify the operating system initiates a screensaver after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable.# # Check to see if GNOME is configured to display a screensaver after a 15 minute delay with the following command:# # # grep -i idle-delay /etc/dconf/db/local.d/*# idle-delay=uint32 900# # If the "idle-delay" setting is missing or is not set to "900" or less, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces.# # Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:# # # touch /etc/dconf/db/local.d/00-screensaver# # Edit "org/gnome/desktop/session" and add or update the following lines:# # # Set the lock time out to 900 seconds before the session is considered idle# idle-delay=uint32 900# # Edit "org/gnome/desktop/screensaver" and add or update the following lines:# # # Set this to true to lock the screen when the screensaver activates# lock-enabled=true# # Set the lock timeout to 180 seconds after the screensaver has been activated# lock-delay=uint32 180# # You must include the "uint32" along with the integer key values as shown.# # Override the user's setting and prevent the user from changing it by editing "/etc/dconf/db/local.d/locks/screensaver" and adding or updating the following lines:# # # Lock desktop screensaver settings# /org/gnome/desktop/session/idle-delay# /org/gnome/desktop/screensaver/lock-enabled# /org/gnome/desktop/screensaver/lock-delay# # Update the system databases:# # # dconf update# # Users must log out and back in again before the system-wide settings take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_010070' do
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
