#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_010050
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000023-GPOS-00006 ####
#
# STIG ID: RHEL-07-010050
#
# Rule ID: SV-86487r1_rule
#
# Vuln ID: V-71863
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000048# The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.# NIST SP 800-53 :: AC-8 a# NIST SP 800-53A :: AC-8.1 (ii)# NIST SP 800-53 Revision 4 :: AC-8 a# ######

### The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a command line user logon. ###
# Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.# # System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.# # The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:# # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.# # By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."# # Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:# # "I've read & consent to terms in IS user agreem't."# # Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007

######
#
# Check:
#
# Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a command line user logon.# # Check to see if the operating system displays a banner at the command line logon screen with the following command:# # # more /etc/issue# # The command should return the following text:# "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.# # By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."# # If the operating system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.# # If the text in the "/etc/issue" file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via the command line by editing the "/etc/issue" file.# # Replace the default text with the Standard Mandatory DoD Notice and Consent Banner. The DoD required text is:# # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.# # By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."#
#
######

require 'spec_helper'

describe '::rhel_07_010050' do
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
