#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021620
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021620
#
# Rule ID: SV-86697r2_rule
#
# Vuln ID: V-72073
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories. ###
# File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.

######
#
# Check:
#
# Verify the file integrity tool is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.# # Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.# # Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:# # # yum list installed aide# # If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.# # If there is no application installed to perform file integrity checks, this is a finding.# # Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory.# # Use the following command to determine if the file is in another location:# # # find / -name aide.conf# # Check the "aide.conf" file to determine if the "sha512" rule has been added to the rule list being applied to the files and directories selection lists.# # An example rule that includes the "sha512" rule follows:# # All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux# /bin All            # apply the custom rule to the files in bin# /sbin All          # apply the same custom rule to the files in sbin# # If the "sha512" rule is not being used on all selection lines in the "/etc/aide.conf" file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding.#
#
######
#
# Fix:
#
# Configure the file integrity tool to use FIPS 140-2 cryptographic hashes for validating file and directory contents.# # If AIDE is installed, ensure the "sha512" rule is present on all file and directory selection lists.#
#
######

require 'spec_helper'

describe '::rhel_07_021620' do
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
