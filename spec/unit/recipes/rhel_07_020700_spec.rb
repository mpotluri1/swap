#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020700
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020700
#
# Rule ID: SV-86655r2_rule
#
# Vuln ID: V-72031
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Local initialization files for local interactive users must be group-owned by the users primary group or root. ###
# Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.

######
#
# Check:
#
# Verify the local initialization files of all local interactive users are group-owned by that user’s primary Group Identifier (GID).# # Check the home directory assignment for all non-privileged users on the system with the following command:# # Note: The example will be for the smithj user, who has a home directory of "/home/smithj" and a primary group of "users".# # # cut -d: -f 1,4,6 /etc/passwd | egrep ":[1-4][0-9]{3}"# smithj:1000:/home/smithj# # # grep 1000 /etc/group# users:x:1000:smithj,jonesj,jacksons# # Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.# # Check the group owner of all local interactive users’ initialization files with the following command:# # # ls -al /home/smithj/.*# -rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile# -rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login# -rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something# # If all local interactive users’ initialization files are not group-owned by that user’s primary GID, this is a finding.#
#
######
#
# Fix:
#
# Change the group owner of a local interactive user’s files to the group found in "/etc/passwd" for the user. To change the group owner of a local interactive user home directory, use the following command:# # Note: The example will be for the user smithj, who has a home directory of "/home/smithj", and has a primary group of users.# # # chgrp users /home/smithj/<file>#
#
######

require 'spec_helper'

describe '::rhel_07_020700' do
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
