#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_031010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-031010
#
# Rule ID: SV-86835r1_rule
#
# Vuln ID: V-72211
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation. ###
# Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service.# If the system is intended to be a log aggregation server its use must be documented with the ISSO.

######
#
# Check:
#
# Verify that the system is not accepting "rsyslog" messages from other systems unless it is documented as a log aggregation server.# # Check the configuration of "rsyslog" with the following command:# # # grep imtcp /etc/rsyslog.conf# ModLoad imtcp# # If the "imtcp" module is being loaded in the "/etc/rsyslog.conf" file, ask to see the documentation for the system being used for log aggregation.# # If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding.#
#
######
#
# Fix:
#
# Modify the "/etc/rsyslog.conf" file to remove the "ModLoad imtcp" configuration line, or document the system as being used for log aggregation.#
#
######

require 'spec_helper'

describe '::rhel_07_031010' do
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
