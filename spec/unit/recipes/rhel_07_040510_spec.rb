#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040510
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000420-GPOS-00186 ####
#
# STIG ID: RHEL-07-040510
#
# Rule ID: SV-86895r1_rule
#
# Vuln ID: V-72271
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-002385# The information system protects against or limits the effects of organization-defined types of denial of service attacks by employing organization-defined security safeguards.# NIST SP 800-53 Revision 4 :: SC-5# ######

### The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces. ###
# DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.# # This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

######
#
# Check:
#
# Verify the operating system protects against or limits the effects of DoS attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.# # Check the firewall configuration with the following command:# # Note: The command is to query rules for the public zone.# # # firewall-cmd --direct --get-rule ipv4 filter IN_public_allow# rule ipv4 filter IN_public_allow 0 -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT# # If a rule with both the limit and limit-burst arguments parameters does not exist, this is a finding.#
#
######
#
# Fix:
#
# Create a direct firewall rule to protect against DoS attacks with the following command:# # Note: The command is to add a rule to the public zone.# # # firewall-cmd --direct --add-rule ipv4 filter IN_public_allow 0 -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT#
#
######

require 'spec_helper'

describe '::rhel_07_040510' do
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
