#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_020260
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000480-GPOS-00227 ####
#
# STIG ID: RHEL-07-020260
#
# Rule ID: SV-86623r3_rule
#
# Vuln ID: V-71999
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000366# The organization implements the security configuration settings.# NIST SP 800-53 :: CM-6 b# NIST SP 800-53A :: CM-6.1 (iv)# NIST SP 800-53 Revision 4 :: CM-6 b# ######

### Vendor packaged system security patches and updates must be installed and up to date. ###
# Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.

######
#
# Check:
#
# Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).# # Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.# # Check that the available package security updates have been installed on the system with the following command:# # # yum history list | more# Loaded plugins: langpacks, product-id, subscription-manager# ID     | Command line             | Date and time    | Action(s)      | Altered# -------------------------------------------------------------------------------# 70 | install aide             | 2016-05-05 10:58 | Install       |     1# 69 | update -y                | 2016-05-04 14:34 | Update     |   18 EE# 68 | install vlc                | 2016-04-21 17:12 | Install        |   21# 67 | update -y                | 2016-04-21 17:04 | Update     |     7 EE# 66 | update -y                | 2016-04-15 16:47 | E, I, U         |   84 EE# # If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding.# # Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.# # If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding.#
#
######
#
# Fix:
#
# Install the operating system patches or updated packages available from Red Hat within 30 days or sooner as local policy dictates.#
#
######

require 'spec_helper'

describe '::rhel_07_020260' do
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
