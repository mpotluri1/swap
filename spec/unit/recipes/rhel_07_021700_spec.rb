#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_021700
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000364-GPOS-00151 ####
#
# STIG ID: RHEL-07-021700
#
# Rule ID: SV-86699r1_rule
#
# Vuln ID: V-72075
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### The system must not allow removable media to be used as the boot loader unless approved. ###
# Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader. If removable media is designed to be used as the boot loader, the requirement must be documented with the Information System Security Officer (ISSO).

######
#
# Check:
#
# Verify the system is not configured to use a boot loader on removable media.# # Note: GRUB 2 reads its configuration from the "/boot/grub2/grub.cfg" file on traditional BIOS-based machines and from the "/boot/efi/EFI/redhat/grub.cfg" file on UEFI machines.# # Check for the existence of alternate boot loader configuration files with the following command:# # # find / -name grub.cfg# /boot/grub2/grub.cfg# # If a "grub.cfg" is found in any subdirectories other than "/boot/grub2" and "/boot/efi/EFI/redhat", ask the System Administrator if there is documentation signed by the ISSO to approve the use of removable media as a boot loader.# # Check that the grub configuration file has the set root command in each menu entry with the following commands:# # # grep -c menuentry /boot/grub2/grub.cfg# 1# # grep ‘set root’ /boot/grub2/grub.cfg# set root=(hd0,1)# # If the system is using an alternate boot loader on removable media, and documentation does not exist approving the alternate configuration, this is a finding.#
#
######
#
# Fix:
#
# Remove alternate methods of booting the system from removable media or document the configuration to boot from removable media with the ISSO.#
#
######

require 'spec_helper'

describe '::rhel_07_021700' do
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
