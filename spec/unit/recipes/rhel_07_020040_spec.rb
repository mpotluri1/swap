#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020040
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000363-GPOS-00150 ####
#
# STIG ID: RHEL-07-020040
#
# Rule ID: SV-86599r1_rule
#
# Vuln ID: V-71975
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001744# The information system implements organization-defined security responses automatically if baseline configurations are changed in an unauthorized manner.# NIST SP 800-53 Revision 4 :: CM-3 (5)# ######

### Designated personnel must be notified if baseline configurations are changed in an unauthorized manner. ###
# Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.# # Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.

######
#
# Check:
#
# Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.# # Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.# # Check to see if AIDE is installed on the system with the following command:# # # yum list installed aide# # If AIDE is not installed, ask the SA how file integrity checks are performed on the system.# # Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.# # Check the "/etc/cron.daily" subdirectory for a "crontab" file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following commands:# # # ls -al /etc/cron.daily | grep aide# -rwxr-xr-x  1 root root        32 Jul  1  2011 aide# # AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:# # # more /etc/cron.daily/aide# 0 0 * * * /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil# # If the file integrity application does not notify designated personnel of changes, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel through the use of the cron system.# # The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis.# # # more /etc/cron.daily/aide# 0 0 * * * /usr/sbin/aide --check | /bin/mail -s "$HOSTNAME - Daily aide integrity check run" root@sysname.mil#
#
######

require 'spec_helper'

describe '::rhel_07_020040' do
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
