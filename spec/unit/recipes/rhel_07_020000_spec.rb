#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020000
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000095-GPOS-00049 ####
#
# STIG ID: RHEL-07-020000
#
# Rule ID: SV-86591r1_rule
#
# Vuln ID: V-71967
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000381# The organization configures the information system to provide only essential capabilities.# NIST SP 800-53 :: CM-7# NIST SP 800-53A :: CM-7.1 (ii)# NIST SP 800-53 Revision 4 :: CM-7 a# ######

### The rsh-server package must not be installed. ###
# It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.# # Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).# # The rsh-server service provides an unencrypted remote access service that does not provide for the confidentiality and integrity of user passwords or the remote session and has very weak authentication.# # If a privileged user were to log on using this service, the privileged user password could be compromised.

######
#
# Check:
#
# Check to see if the rsh-server package is installed with the following command:# # # yum list installed rsh-server# # If the rsh-server package is installed, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to disable non-essential capabilities by removing the rsh-server package from the system with the following command:# # # yum remove rsh-server#
#
######

require 'spec_helper'

describe '::rhel_07_020000' do
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
