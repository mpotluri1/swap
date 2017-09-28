#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020240
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00228 ####
#
# STIG ID: RHEL-07-020240
#
# Rule ID: SV-86619r1_rule
#
# Vuln ID: V-71995
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files. ###
# Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.

######
#
# Check:
#
# Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.# # Check for the value of the "UMASK" parameter in "/etc/login.defs" file with the following command:# # Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.# # # grep -i umask /etc/login.defs# UMASK  077# # If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.# # Add or edit the line for the "UMASK" parameter in "/etc/login.defs" file to "077":# # UMASK  077#
#
######

require 'spec_helper'

describe '::rhel_07_020240' do
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
