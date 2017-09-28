#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020300
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000104-GPOS-00051 ####
#
# STIG ID: RHEL-07-020300
#
# Rule ID: SV-86627r1_rule
#
# Vuln ID: V-72003
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000764# The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).# NIST SP 800-53 :: IA-2# NIST SP 800-53A :: IA-2.1# NIST SP 800-53 Revision 4 :: IA-2# ######

### All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file. ###
# If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.

######
#
# Check:
#
# Verify all GIDs referenced in the "/etc/passwd" file are defined in the "/etc/group" file.# # Check that all referenced GIDs exist with the following command:# # # pwck -r# # If GIDs referenced in "/etc/passwd" file are returned as not defined in "/etc/group" file, this is a finding.#
#
######
#
# Fix:
#
# Configure the system to define all GIDs found in the "/etc/passwd" file by modifying the "/etc/group" file to add any non-existent group referenced in the "/etc/passwd" file, or change the GIDs referenced in the "/etc/passwd" file to a group that exists in "/etc/group".#
#
######

require 'spec_helper'

describe '::rhel_07_020300' do
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
