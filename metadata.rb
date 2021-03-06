name 'swap_file' # ~FC064 ~FC065 ~FC078
maintainer 'REAN Cloud LLC'
maintainer_email 'noel.georgi@reancloud.com'
license 'All Rights Reserved'
description 'Installs/Configures STIG-RHEL-7'
long_description 'Installs/Configures STIG-RHEL-7'
version '0.1.0'
chef_version '>= 12.1' if respond_to?(:chef_version)

# Option I:
# supports 'ubuntu', '= 14.04'
# supports 'fedora', '> 25'
supports 'redhat', '=7.4'

# Option II:
# platforms =
#   [
#     {
#       'name' => 'windows',
#       'version' => '> 2008'
#     },
#     {
#       'name' => 'ubuntu',
#       'version' => '< 14.04'
#     },
#     {
#       'name' => 'redhat',
#       'version' => '= 6'
#     }
#   ]

# platforms.each do |_list|
#   supports _list['name'], _list['version']
# end

# The platform support should be added as per any of the options abo

