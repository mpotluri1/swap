#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010450
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00229 ####
#
# STIG ID: RHEL-07-010450
#
# Rule ID: SV-86579r2_rule
#
# Vuln ID: V-71955
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The operating system must not allow an unrestricted logon to the system. ###
# Failure to restrict system access to authenticated users negatively impacts operating system security.

######
#
# Check:
#
# Verify the operating system does not allow an unrestricted logon to the system via a graphical user interface.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable.# # Check for the value of the "TimedLoginEnable" parameter in "/etc/gdm/custom.conf" file with the following command:# # # grep -i timedloginenable /etc/gdm/custom.conf# TimedLoginEnable=false# # If the value of "TimedLoginEnable" is not set to "false", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to not allow an unrestricted account to log on to the system via a graphical user interface.# # Note: If the system does not have GNOME installed, this requirement is Not Applicable.# # Add or edit the line for the "TimedLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false":# # [daemon]# TimedLoginEnable=false#
#
######

require 'spec_helper'

describe '::rhel_07_010450' do
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
