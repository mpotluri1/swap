#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020060
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000366-GPOS-00153 ####
#
# STIG ID: RHEL-07-020060
#
# Rule ID: SV-86603r1_rule
#
# Vuln ID: V-71979
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001749# The information system prevents the installation of organization-defined software components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.# NIST SP 800-53 Revision 4 :: CM-5 (3)# ######

### The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of local packages without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization. ###
# Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.# # Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.# # Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.

######
#
# Check:
#
# Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.# # Check that yum verifies the signature of local packages prior to install with the following command:# # # grep localpkg_gpgcheck /etc/yum.conf# localpkg_gpgcheck=1# # If "localpkg_gpgcheck" is not set to "1", or if options are missing or commented out, ask the System Administrator how the signatures of local packages and other operating system components are verified.# # If there is no process to validate the signatures of local packages that is approved by the organization, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to verify the signature of local packages prior to install by setting the following option in the "/etc/yum.conf" file:# # localpkg_gpgcheck=1#
#
######

require 'spec_helper'

describe '::rhel_07_020060' do
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
