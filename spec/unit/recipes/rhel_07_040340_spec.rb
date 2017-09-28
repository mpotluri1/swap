#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040340
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000163-GPOS-00072 ####
#
# STIG ID: RHEL-07-040340
#
# Rule ID: SV-86865r2_rule
#
# Vuln ID: V-72241
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-001133# The information system terminates the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.# NIST SP 800-53 :: SC-10# NIST SP 800-53A :: SC-10.1 (ii)# NIST SP 800-53 Revision 4 :: SC-10# # CCI-002361# The information system automatically terminates a user session after organization-defined conditions or trigger events requiring session disconnect.# NIST SP 800-53 Revision 4 :: AC-12# ######

### All network connections associated with SSH traffic must terminate after a period of inactivity. ###
# Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.# # Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.# # Satisfies: SRG-OS-000163-GPOS-00072, SRG-OS-000279-GPOS-00109

######
#
# Check:
#
# Verify the operating system automatically terminates a user session after inactivity time-outs have expired.# # Check for the value of the "ClientAliveCountMax" keyword with the following command:# # # grep -i clientalivecount /etc/ssh/sshd_config# ClientAliveCountMax 0# # If "ClientAliveCountMax" is not set to "0" in "/etc/ ssh/sshd_config", this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to automatically terminate a user session after inactivity time-outs have expired or at shutdown.# # Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):# # ClientAliveCountMax 0# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040340' do
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
