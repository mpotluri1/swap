#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010480
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000080-GPOS-00048 ####
#
# STIG ID: RHEL-07-010480
#
# Rule ID: SV-86585r1_rule
#
# Vuln ID: V-71961
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000213# The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.# NIST SP 800-53 :: AC-3# NIST SP 800-53A :: AC-3.1# NIST SP 800-53 Revision 4 :: AC-3# ######

### Systems with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes. ###
# If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.

######
#
# Check:
#
# Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:# # # grep -i password /boot/grub2/grub.cfg# password_pbkdf2 superusers-account password-hash# # If the root password entry does not begin with "password_pbkdf2", this is a finding.#
#
######
#
# Fix:
#
# Configure the system to encrypt the boot password for root.# # Generate an encrypted grub2 password for root with the following command:# # Note: The hash generated is an example.# # # grub-mkpasswd-pbkdf2# Enter Password:# Reenter Password:# PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45# # Using this hash, modify the "/etc/grub.d/10_linux" file with the following commands to add the password to the root entry:# # # cat << EOF# > set superusers="root" password_pbkdf2 smithj grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45# > EOF# # Generate a new "grub.conf" file with the new password with the following commands:# # # grub2-mkconfig --output=/tmp/grub2.cfg# # mv /tmp/grub2.cfg /boot/grub2/grub.cfg#
#
######

require 'spec_helper'

describe '::rhel_07_010480' do
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
