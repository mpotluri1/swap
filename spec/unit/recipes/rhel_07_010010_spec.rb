#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000257-GPOS-00098 ####
#
# STIG ID: RHEL-07-010010
#
# Rule ID: SV-86473r2_rule
#
# Vuln ID: V-71849
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001494# The information system protects audit tools from unauthorized modification.# NIST SP 800-53 :: AU-9# NIST SP 800-53A :: AU-9.1# NIST SP 800-53 Revision 4 :: AU-9# # CCI-001496# The information system implements cryptographic mechanisms to protect the integrity of audit tools.# NIST SP 800-53 :: AU-9 (3)# NIST SP 800-53A :: AU-9 (3).1# NIST SP 800-53 Revision 4 :: AU-9 (3)# ######

### The file permissions, ownership, and group membership of system files and commands must match the vendor values. ###
# Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.# # Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108

######
#
# Check:
#
# Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.# # Check the file permissions, ownership, and group membership of system files and commands with the following command:# # # rpm -Va | grep '^.M'# # If there is any output from the command indicating that the ownership or group of a system file or command, or a system file, has permissions less restrictive than the default, this is a finding.#
#
######
#
# Fix:
#
# Run the following command to determine which package owns the file:# # # rpm -qf <filename># # Reset the permissions of files within a package with the following command:# # #rpm --setperms <packagename># # Reset the user and group ownership of files within a package with the following command:# # #rpm --setugids <packagename>#
#
######

require 'spec_helper'

describe '::rhel_07_010010' do
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
