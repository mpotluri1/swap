#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010110
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000029-GPOS-00010 ####
#
# STIG ID: RHEL-07-010110
#
# Rule ID: SV-86525r1_rule
#
# Vuln ID: V-71901
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000057# The information system initiates a session lock after the organization-defined time period of inactivity.# NIST SP 800-53 :: AC-11 a# NIST SP 800-53A :: AC-11.1 (ii)# NIST SP 800-53 Revision 4 :: AC-11 a# ######

### The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated. ###
# A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.# # The session lock is implemented at the point where session activity can be determined and/or controlled.

######
#
# Check:
#
# Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated. The screen program must be installed to lock sessions on the console.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable.# # If GNOME is installed, check to see a session lock occurs when the screensaver is activated with the following command:# # # grep -i lock-delay /etc/dconf/db/local.d/*# lock-delay=uint32 5# # If the "lock-delay" setting is missing, or is not set, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to initiate a session lock for graphical user interfaces when a screensaver is activated.# # Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:# # # touch /etc/dconf/db/local.d/00-screensaver# # Add the setting to enable session locking when a screensaver is activated:# # [org/gnome/desktop/screensaver]# lock-delay=uint32 5# # After the setting has been set, run dconf update.#
#
######

require 'spec_helper'

describe '::rhel_07_010110' do
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
