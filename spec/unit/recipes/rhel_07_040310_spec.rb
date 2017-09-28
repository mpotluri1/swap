#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040310
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000423-GPOS-00187 ####
#
# STIG ID: RHEL-07-040310
#
# Rule ID: SV-86859r2_rule
#
# Vuln ID: V-72235
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002418# The information system protects the confidentiality and/or integrity of transmitted information.# NIST SP 800-53 Revision 4 :: SC-8# # CCI-002420# The information system maintains the confidentiality and/or integrity of information during preparation for transmission.# NIST SP 800-53 Revision 4 :: SC-8 (2)# # CCI-002421# The information system implements cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by organization-defined alternative physical safeguards.# NIST SP 800-53 Revision 4 :: SC-8 (1)# # CCI-002422# The information system maintains the confidentiality and/or integrity of information during reception.# NIST SP 800-53 Revision 4 :: SC-8 (2)# ######

### All networked systems must use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission. ###
# Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.# # This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.# # Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.# # Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000423-GPOS-00188, SRG-OS-000423-GPOS-00189, SRG-OS-000423-GPOS-00190

######
#
# Check:
#
# Verify SSH is loaded and active with the following command:# # # systemctl status sshd# sshd.service - OpenSSH server daemon# Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)# Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago# Main PID: 1348 (sshd)# CGroup: /system.slice/sshd.service# ??1348 /usr/sbin/sshd -D# # If "sshd" does not show a status of "active" and "running", this is a finding.#
#
######
#
# Fix:
#
# Configure the SSH service to automatically start after reboot with the following command:# # # systemctl enable sshd ln -s '/usr/lib/systemd/system/sshd.service' '/etc/systemd/system/multi-user.target.wants/sshd.service'#
#
######

require 'spec_helper'

describe '::rhel_07_040310' do
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
