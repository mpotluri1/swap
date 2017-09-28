#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030360
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000327-GPOS-00127 ####
#
# STIG ID: RHEL-07-030360
#
# Rule ID: SV-86719r2_rule
#
# Vuln ID: V-72095
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002234# The information system audits the execution of privileged functions.# NIST SP 800-53 Revision 4 :: AC-6 (9)# ######

### All privileged function executions must be audited. ###
# Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

######
#
# Check:
#
# Verify the operating system audits the execution of privileged functions.# # To find relevant setuid and setgid programs, use the following command once for each local partition [PART]:# # # find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null# # Run the following command to verify entries in the audit rules for all programs found with the previous command:# # # grep <suid_prog_with_full_path> -a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid# # All "setuid" and "setgid" files on the system must have a corresponding audit rule, or must have an audit rule for the (sub) directory that contains the "setuid"/"setgid" file.# # If all "setuid"/"setgid" files on the system do not have audit rule coverage, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to audit the execution of privileged functions.# # To find the relevant "setuid"/"setgid" programs, run the following command for each local partition [PART]:# # # find [PART] -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null# # For each "setuid"/"setgid" program on the system, which is not covered by an audit rule for a (sub) directory (such as "/usr/sbin"), add a line of the following form to "/etc/audit/audit.rules", where <suid_prog_with_full_path> is the full path to each "setuid"/"setgid" program in the list:# # -a always,exit -F <suid_prog_with_full_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k setuid/setgid#
#
######

require 'spec_helper'

describe '::rhel_07_030360' do
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
