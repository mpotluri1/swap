#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021600
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021600
#
# Rule ID: SV-86693r2_rule
#
# Vuln ID: V-72069
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### The file integrity tool must be configured to verify Access Control Lists (ACLs). ###
# ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.

######
#
# Check:
#
# Verify the file integrity tool is configured to verify ACLs.# # Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:# # # yum list installed aide# # If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.# # If there is no application installed to perform file integrity checks, this is a finding.# # Note: AIDE is highly configurable at install time. These commands assume the "aide.conf" file is under the "/etc" directory.# # Use the following command to determine if the file is in another location:# # # find / -name aide.conf# # Check the "aide.conf" file to determine if the "acl" rule has been added to the rule list being applied to the files and directories selection lists.# # An example rule that includes the "acl" rule is below:# # All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux# /bin All            # apply the custom rule to the files in bin# /sbin All          # apply the same custom rule to the files in sbin# # If the "acl" rule is not being used on all selection lines in the "/etc/aide.conf" file, or ACLs are not being checked by another file integrity tool, this is a finding.#
#
######
#
# Fix:
#
# Configure the file integrity tool to check file and directory ACLs.# # If AIDE is installed, ensure the "acl" rule is present on all file and directory selection lists.#
#
######

require 'spec_helper'

describe '::rhel_07_021600' do
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
