#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040440
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000364-GPOS-00151 ####
#
# STIG ID: RHEL-07-040440
#
# Rule ID: SV-86885r2_rule
#
# Vuln ID: V-72261
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000318# The organization audits and reviews activities associated with configuration controlled changes to the system.# NIST SP 800-53 :: CM-3 e# NIST SP 800-53A :: CM-3.1 (v)# NIST SP 800-53 Revision 4 :: CM-3 f# # CCI-000368# The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.# NIST SP 800-53 :: CM-6 c# NIST SP 800-53A :: CM-6.1 (v)# NIST SP 800-53 Revision 4 :: CM-6 c# # CCI-001812# The information system prohibits user installation of software without explicit privileged status.# NIST SP 800-53 Revision 4 :: CM-11 (2)# # CCI-001813# The information system enforces access restrictions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# # CCI-001814# The Information system supports auditing of the enforcement actions.# NIST SP 800-53 Revision 4 :: CM-5 (1)# ######

### The SSH daemon must not permit Kerberos authentication unless needed. ###
# Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled for systems not using this capability.

######
#
# Check:
#
# Verify the SSH daemon does not permit Kerberos to authenticate passwords unless approved.# # Check that the SSH daemon does not permit Kerberos to authenticate passwords with the following command:# # # grep -i kerberosauth /etc/ssh/sshd_config# KerberosAuthentication no# # If the "KerberosAuthentication" keyword is missing, or is set to "yes" and is not documented with the Information System Security Officer (ISSO), or the returned line is commented out, this is a finding.#
#
######
#
# Fix:
#
# Uncomment the "KerberosAuthentication" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "no":# # KerberosAuthentication no# # The SSH service must be restarted for changes to take effect.# # If Kerberos authentication is required, it must be documented, to include the location of the configuration file, with the ISSO.#
#
######

require 'spec_helper'

describe '::rhel_07_040440' do
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
