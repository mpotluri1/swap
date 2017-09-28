#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040700
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-040700
#
# Rule ID: SV-86925r1_rule
#
# Vuln ID: V-72301
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support. ###
# If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.

######
#
# Check:
#
# Verify a TFTP server has not been installed on the system.# # Check to see if a TFTP server has been installed with the following command:# # # yum list installed tftp-server# tftp-server-0.49-9.el7.x86_64.rpm# # If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.#
#
######
#
# Fix:
#
# Remove the TFTP package from the system with the following command:# # # yum remove tftp#
#
######

require 'spec_helper'

describe '::rhel_07_040700' do
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
