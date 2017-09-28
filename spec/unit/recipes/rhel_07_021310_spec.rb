#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021310
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-021310
#
# Rule ID: SV-86683r1_rule
#
# Vuln ID: V-72059
#
# Severity: low
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### A separate file system must be used for user home directories (such as /home or an equivalent). ###
# The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.

######
#
# Check:
#
# Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.# # Check the home directory assignment for all non-privileged users (those with a UID greater than 1000) on the system with the following command:# # #cut -d: -f 1,3,6,7 /etc/passwd | egrep ":[1-4][0-9]{3}" | tr ":" "\t"# # adamsj /home/adamsj /bin/bash# jacksonm /home/jacksonm /bin/bash# smithj /home/smithj /bin/bash# # The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.# # Check that a file system/partition has been created for the non-privileged interactive users with the following command:# # Note: The partition of /home is used in the example.# # # grep /home /etc/fstab# UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2# # If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding.#
#
######
#
# Fix:
#
# Migrate the "/home" directory onto a separate file system/partition.#
#
######

require 'spec_helper'

describe '::rhel_07_021310' do
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
