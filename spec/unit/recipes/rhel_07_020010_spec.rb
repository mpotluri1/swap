#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020010
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000095-GPOS-00049 ####
#
# STIG ID: RHEL-07-020010
#
# Rule ID: SV-86593r1_rule
#
# Vuln ID: V-71969
#
# Severity: high
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000381# The organization configures the information system to provide only essential capabilities.# NIST SP 800-53 :: CM-7# NIST SP 800-53A :: CM-7.1 (ii)# NIST SP 800-53 Revision 4 :: CM-7 a# ######

### The ypserv package must not be installed. ###
# Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.

######
#
# Check:
#
# The NIS service provides an unencrypted authentication service that does not provide for the confidentiality and integrity of user passwords or the remote session.# # Check to see if the "ypserve" package is installed with the following command:# # # yum list installed ypserv# # If the "ypserv" package is installed, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to disable non-essential capabilities by removing the "ypserv" package from the system with the following command:# # # yum remove ypserv#
#
######

require 'spec_helper'

describe '::rhel_07_020010' do
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
