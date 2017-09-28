#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040100
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000096-GPOS-00050 ####
#
# STIG ID: RHEL-07-040100
#
# Rule ID: SV-86843r1_rule
#
# Vuln ID: V-72219
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000382# The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.# NIST SP 800-53 :: CM-7# NIST SP 800-53A :: CM-7.1 (iii)# NIST SP 800-53 Revision 4 :: CM-7 b# # CCI-002314# The information system controls remote access methods.# NIST SP 800-53 Revision 4 :: AC-17 (1)# ######

### The host must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the Ports, Protocols, and Services Management Component Local Service Assessment (PPSM CLSA) and vulnerability assessments. ###
# In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.# # Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.# # To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.# # Satisfies: SRG-OS-000096-GPOS-00050, SRG-OS-000297-GPOS-00115

######
#
# Check:
#
# Inspect the firewall configuration and running services to verify that it is configured to prohibit or restrict the use of functions, ports, protocols, and/or services that are unnecessary or prohibited.# # Check which services are currently active with the following command:# # # firewall-cmd --list-all# public (default, active)# interfaces: enp0s3# sources:# services: dhcpv6-client dns http https ldaps rpc-bind ssh# ports:# masquerade: no# forward-ports:# icmp-blocks:# rich rules:# # Ask the System Administrator for the site or program PPSM CLSA. Verify the services allowed by the firewall match the PPSM CLSA.# # If there are additional ports, protocols, or services that are not in the PPSM CLSA, or there are ports, protocols, or services that are prohibited by the PPSM Category Assurance List (CAL), this is a finding.#
#
######
#
# Fix:
#
# Update the host's firewall settings and/or running services to comply with the PPSM CLSA for the site or program and the PPSM CAL.#
#
######

require 'spec_helper'

describe '::rhel_07_040100' do
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
