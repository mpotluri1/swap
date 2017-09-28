#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020200
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000437-GPOS-00194 ####
#
# STIG ID: RHEL-07-020200
#
# Rule ID: SV-86611r1_rule
#
# Vuln ID: V-71987
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002617# The organization removes organization-defined software components (e.g., previous versions) after updated versions have been installed.# NIST SP 800-53 Revision 4 :: SI-2 (6)# ######

### The operating system must remove all software components after updated versions have been installed. ###
# Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

######
#
# Check:
#
# Verify the operating system removes all software components after updated versions have been installed.# # Check if yum is configured to remove unneeded packages with the following command:# # # grep -i clean_requirements_on_remove /etc/yum.conf# clean_requirements_on_remove=1# # If "clean_requirements_on_remove" is not set to "1", "True", or "yes", or is not set in "/etc/yum.conf", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to remove all software components after updated versions have been installed.# # Set the "clean_requirements_on_remove" option to "1" in the "/etc/yum.conf" file:# # clean_requirements_on_remove=1#
#
######

require 'spec_helper'

describe '::rhel_07_020200' do
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
