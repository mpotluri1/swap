#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020900
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020900
#
# Rule ID: SV-86663r1_rule
#
# Vuln ID: V-72039
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### All system device files must be correctly labeled to prevent unauthorized modification. ###
# If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.

######
#
# Check:
#
# Verify that all system device files are correctly labeled to prevent unauthorized modification.# # List all device files on the system that are incorrectly labeled with the following commands:# # Note: Device files are normally found under "/dev", but applications may place device files in other directories and may necessitate a search of the entire system.# # #find /dev -context *:device_t:* \( -type c -o -type b \) -printf "%p %Z\n"# # #find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf "%p %Z\n"# # Note: There are device files, such as "/dev/vmci", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the "device_t" label to operate. These device files are not a finding.# # If there is output from either of these commands, other than already noted, this is a finding.#
#
######
#
# Fix:
#
# Run the following command to determine which package owns the device file:# # # rpm -qf <filename># # The package can be reinstalled from a yum repository using the command:# # # sudo yum reinstall <packagename># # Alternatively, the package can be reinstalled from trusted media using the command:# # # sudo rpm -Uvh <packagename>#
#
######

require 'spec_helper'

describe '::rhel_07_020900' do
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
