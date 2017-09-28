#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040500
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000355-GPOS-00143 ####
#
# STIG ID: RHEL-07-040500
#
# Rule ID: SV-86893r2_rule
#
# Vuln ID: V-72269
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001891# The information system compares internal information system clocks on an organization-defined frequency with an organization-defined authoritative time source.# NIST SP 800-53 Revision 4 :: AU-8 (1) (a)# # CCI-002046# The information system synchronizes the internal system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.# NIST SP 800-53 Revision 4 :: AU-8 (1) (b)# ######

### The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). ###
# Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.# # Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.# # Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).# # Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000356-GPOS-00144

######
#
# Check:
#
# Check to see if NTP is running in continuous mode.# # # ps -ef | grep ntp# # If NTP is not running, this is a finding.# # If the process is found, then check the "ntp.conf" file for the "maxpoll" option setting:# # # grep maxpoll /etc/ntp.conf# # maxpoll 17# # If the option is set to "17" or is not set, this is a finding.# # If the file does not exist, check the "/etc/cron.daily" subdirectory for a crontab file controlling the execution of the "ntpdate" command.# # # grep -l ntpdate /etc/cron.daily# # # ls -al /etc/cron.* | grep aide# ntp# # If a crontab file does not exist in the "/etc/cron.daily" that executes the "ntpdate" file, this is a finding.#
#
######
#
# Fix:
#
# Edit the "/etc/ntp.conf" file and add or update an entry to define "maxpoll" to "10" as follows:# # maxpoll 10# # If NTP was running and "maxpoll" was updated, the NTP service must be restarted:# # # systemctl restart ntpd# # If NTP was not running, it must be started:# # # systemctl start ntpd#
#
######

require 'spec_helper'

describe '::rhel_07_040500' do
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
