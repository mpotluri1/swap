#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_030010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000046-GPOS-00022 ####
#
# STIG ID: RHEL-07-030010
#
# Rule ID: SV-86705r1_rule
#
# Vuln ID: V-72081
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000139# The information system alerts designated organization-defined personnel or roles in the event of an audit processing failure.# NIST SP 800-53 :: AU-5 a# NIST SP 800-53A :: AU-5.1 (ii)# NIST SP 800-53 Revision 4 :: AU-5 a# ######

### The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure. ###
# It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.# # Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.# # This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.# # Satisfies: SRG-OS-000046-GPOS-00022, SRG-OS-000047-GPOS-00023

######
#
# Check:
#
# Confirm the audit configuration regarding how auditing processing failures are handled.# # Check to see what level "auditctl" is set to with following command:# # # auditctl -l | grep /-f# -f 2# # If the value of "-f" is set to "2", the system is configured to panic (shut down) in the event of an auditing failure.# # If the value of "-f" is set to "1", the system is configured to only send information to the kernel log regarding the failure.# # If the "-f" flag is not set, this is a CAT I finding.# # If the "-f" flag is set to any value other than "1" or "2", this is a CAT II finding.# # If the "-f" flag is set to "1" but the availability concern is not documented or there is no monitoring of the kernel log, this is a CAT III finding.#
#
######
#
# Fix:
#
# Configure the operating system to shut down in the event of an audit processing failure.# # Add or correct the option to shut down the operating system with the following command:# # # auditctl -f 2# # If availability has been determined to be more important, and this decision is documented with the ISSO, configure the operating system to notify system administration staff and ISSO staff in the event of an audit processing failure with the following command:# # # auditctl -f 1# # Kernel log monitoring must also be configured to properly alert designated staff.# # The audit daemon must be restarted for the changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_030010' do
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
