#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020030
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000363-GPOS-00150 ####
#
# STIG ID: RHEL-07-020030
#
# Rule ID: SV-86597r1_rule
#
# Vuln ID: V-71973
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001744# The information system implements organization-defined security responses automatically if baseline configurations are changed in an unauthorized manner.# NIST SP 800-53 Revision 4 :: CM-3 (5)# ######

### A file integrity tool must verify the baseline operating system configuration at least weekly. ###
# Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.# # Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

######
#
# Check:
#
# Verify the operating system routinely checks the baseline configuration for unauthorized changes.# # Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.# # Check to see if AIDE is installed on the system with the following command:# # # yum list installed aide# # If AIDE is not installed, ask the SA how file integrity checks are performed on the system.# # Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.# # Check the "/etc/cron.daily" subdirectory for a "crontab" file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:# # # ls -al /etc/cron.* | grep aide# -rwxr-xr-x  1 root root        29 Nov  22  2015 aide# # If the file integrity application does not exist, or a "crontab" file does not exist in the "/etc/cron.daily" or "/etc/cron.weekly" subdirectories, this is a finding.#
#
######
#
# Fix:
#
# Configure the file integrity tool to automatically run on the system at least weekly. The following example output is generic. It will set cron to run AIDE daily, but other file integrity tools may be used:# # # cat /etc/cron.daily/aide# 0 0 * * * /usr/sbin/aide --check | /bin/mail -s "aide integrity check run for <system name>" root@sysname.mil#
#
######

require 'spec_helper'

describe '::rhel_07_020030' do
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
