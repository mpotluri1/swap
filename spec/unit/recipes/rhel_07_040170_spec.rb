#
# Cookbook:: STIG-RHEL-7
# Recipe:: rhel_07_040170
# Spec:: default
# Source Red Hat Enterprise Linux 7 Security Technical Implementation Guide :: Release: 1 Benchmark Date: 27 Feb 2017
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#### SRG-OS-000023-GPOS-00006 ####
#
# STIG ID: RHEL-07-040170
#
# Rule ID: SV-86849r2_rule
#
# Vuln ID: V-72225
#
# Severity: medium
#
# Class: Unclass
#
# Vulnerability Management Service Asset Posture: 2777
#
# Control Correlation Identifiers:
# CCI-000048# The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.# NIST SP 800-53 :: AC-8 a# NIST SP 800-53A :: AC-8.1 (ii)# NIST SP 800-53 Revision 4 :: AC-8 a# # CCI-000050# The information system retains the notification message or banner on the screen until users acknowledge the usage conditions and take explicit actions to log on to or further access.# NIST SP 800-53 :: AC-8 b# NIST SP 800-53A :: AC-8.1 (iii)# NIST SP 800-53 Revision 4 :: AC-8 b# # CCI-001384# The information system, for publicly accessible systems, displays system use information organization-defined conditions before granting further access.# NIST SP 800-53 :: AC-8 c# NIST SP 800-53A :: AC-8.2 (i)# NIST SP 800-53 Revision 4 :: AC-8 c 1# # CCI-001385# The information system, for publicly accessible systems, displays references, if any, to monitoring that are consistent with privacy accommodations for such systems that generally prohibit those activities.# NIST SP 800-53 :: AC-8 c# NIST SP 800-53A :: AC-8.2 (ii)# NIST SP 800-53 Revision 4 :: AC-8 c 2# # CCI-001386# The information system for publicly accessible systems displays references, if any, to recording that are consistent with privacy accommodations for such systems that generally prohibit those activities.# NIST SP 800-53 :: AC-8 c# NIST SP 800-53A :: AC-8.2 (ii)# NIST SP 800-53 Revision 4 :: AC-8 c 2# # CCI-001387# The information system for publicly accessible systems displays references, if any, to auditing that are consistent with privacy accommodations for such systems that generally prohibit those activities.# NIST SP 800-53 :: AC-8 c# NIST SP 800-53A :: AC-8.2 (ii)# NIST SP 800-53 Revision 4 :: AC-8 c 2# # CCI-001388# The information system, for publicly accessible systems, includes a description of the authorized uses of the system.# NIST SP 800-53 :: AC-8 c# NIST SP 800-53A :: AC-8.2 (iii)# NIST SP 800-53 Revision 4 :: AC-8 c 3# ######

### The Standard Mandatory DoD Notice and Consent Banner must be displayed immediately prior to, or as part of, remote access logon prompts. ###
# Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.# # System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.# # The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:# # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.# # By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."# # Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007 , SRG-OS-000228-GPOS-00088

######
#
# Check:
#
# Verify any publicly accessible connection to the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.# # Check for the location of the banner file being used with the following command:# # # grep -i banner /etc/ssh/sshd_config# # banner=/etc/issue# # This command will return the banner keyword and the name of the file that contains the ssh banner (in this case "/etc/issue").# # If the line is commented out, this is a finding.# # View the file specified by the banner keyword to check that it matches the text of the Standard Mandatory DoD Notice and Consent Banner:# # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."# # If the system does not display a graphical logon banner or the banner does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.# # If the text in the file does not match the Standard Mandatory DoD Notice and Consent Banner, this is a finding.#
#
######
#
# Fix:
#
# Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system via the ssh.# # Edit the "/etc/ssh/sshd_config" file to uncomment the banner keyword and configure it to point to a file that will contain the logon banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). An example configuration line is:# # banner=/etc/issue# # Either create the file containing the banner or replace the text in the file with the Standard Mandatory DoD Notice and Consent Banner. The DoD required text is:# # "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:# # -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.# # -At any time, the USG may inspect and seize data stored on this IS.# # -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.# # -This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.# # -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."# # The SSH service must be restarted for changes to take effect.#
#
######

require 'spec_helper'

describe '::rhel_07_040170' do
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
