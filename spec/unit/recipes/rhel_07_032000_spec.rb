#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_032000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-032000
#
# Rule ID: SV-86837r1_rule
#
# Vuln ID: V-72213
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001668# The organization employs malicious code protection mechanisms at workstations, servers, or mobile computing devices on the network to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means or inserted through the exploitation of information system vulnerabilities.# NIST SP 800-53 :: SI-3 a# NIST SP 800-53A :: SI-3.1 (ii)# ######

### The system must use a DoD-approved virus scan program. ###
# Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.# # The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.# # If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.

######
#
# Check:
#
# Verify the system is using a DoD-approved virus scan program.# # Check for the presence of "McAfee VirusScan Enterprise for Linux" with the following command:# # # systemctl status nails# nails - service for McAfee VirusScan Enterprise for Linux# >  Loaded: loaded /opt/NAI/package/McAfeeVSEForLinux/McAfeeVSEForLinux-2.0.2.<build_number>; enabled)# >  Active: active (running) since Mon 2015-09-27 04:11:22 UTC;21 min ago# # If the "nails" service is not active, check for the presence of "clamav" on the system with the following command:# # # systemctl status clamav-daemon.socket# systemctl status clamav-daemon.socket# clamav-daemon.socket - Socket for Clam AntiVirus userspace daemon# Loaded: loaded (/lib/systemd/system/clamav-daemon.socket; enabled)# Active: active (running) since Mon 2015-01-12 09:32:59 UTC; 7min ago# # If neither of these applications are loaded and active, ask the System Administrator if there is an antivirus package installed and active on the system.# # If no antivirus scan program is active on the system, this is a finding.#
#
######
#
# Fix:
#
# Install an approved DoD antivirus solution on the system.#
#
######

require 'spec_helper'

describe '::rhel_07_032000' do
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
