#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_041003
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000375-GPOS-00160 ####
#
# STIG ID: RHEL-07-041003
#
# Rule ID: SV-87057r2_rule
#
# Vuln ID: V-72433
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001948# The information system implements multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.# NIST SP 800-53 Revision 4 :: IA-2 (11)# # CCI-001953# The information system accepts Personal Identity Verification (PIV) credentials.# NIST SP 800-53 Revision 4 :: IA-2 (12)# # CCI-001954# The information system electronically verifies Personal Identity Verification (PIV) credentials.# NIST SP 800-53 Revision 4 :: IA-2 (12)# ######

### The operating system must implement certificate status checking for PKI authentication. ###
# Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.# # Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.# # A privileged account is defined as an information system account with authorizations of a privileged user.# # Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.# # This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).# # Requires further clarification from NIST.# # Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162

######
#
# Check:
#
# Verify the operating system implements certificate status checking for PKI authentication.# # Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system with the following command:# # # grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf# # cert_policy =ca, ocsp_on, signature;# cert_policy =ca, ocsp_on, signature;# cert_policy =ca, ocsp_on, signature;# # There should be at least three lines returned. All lines must match the example output; specifically that "oscp_on" must be included in the "cert_policy" line.# # If "oscp_on" is present in all "cert_policy" lines, this is not a finding.#
#
######
#
# Fix:
#
# Configure the operating system to do certificate status checking for PKI authentication.# # Modify all of the "cert_policy" lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ocsp_on".#
#
######

require 'spec_helper'

describe '::rhel_07_041003' do
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