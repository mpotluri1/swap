#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010060
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000028-GPOS-00009 ####
#
# STIG ID: RHEL-07-010060
#
# Rule ID: SV-86515r2_rule
#
# Vuln ID: V-71891
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000056# The information system retains the session lock until the user reestablishes access using established identification and authentication procedures.# NIST SP 800-53 :: AC-11 b# NIST SP 800-53A :: AC-11.1 (iii)# NIST SP 800-53 Revision 4 :: AC-11 b# ######

### The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures. ###
# A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.# # The session lock is implemented at the point where session activity can be determined.# # Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.# # Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011

######
#
# Check:
#
# Verify the operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures. The screen program must be installed to lock sessions on the console.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable.# # Check to see if the screen lock is enabled with the following command:# # # grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver# lock-enabled=true# # If the "lock-enabled" setting is missing or is not set to "true", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.# # Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:# # # touch /etc/dconf/db/local.d/00-screensaver# # Edit "org/gnome/desktop/session" and add or update the following lines:# # # Set the lock time out to 900 seconds before the session is considered idle# idle-delay=uint32 900# # Edit "org/gnome/desktop/screensaver" and add or update the following lines:# # # Set this to true to lock the screen when the screensaver activates# lock-enabled=true# # Set the lock timeout to 180 seconds after the screensaver has been activated# lock-delay=uint32 180# # You must include the "uint32" along with the integer key values as shown.# # Override the user's setting and prevent the user from changing it by editing "/etc/dconf/db/local.d/locks/screensaver" and adding or updating the following lines:# # # Lock desktop screensaver settings# /org/gnome/desktop/session/idle-delay# /org/gnome/desktop/screensaver/lock-enabled# /org/gnome/desktop/screensaver/lock-delay# # Update the system databases:# # # dconf update# # Users must log out and back in again before the system-wide settings take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_010060' do
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
