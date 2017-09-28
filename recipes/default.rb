#
# Cookbook:: swap_file
# Recipe:: default
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

#include_recipe 'swap::default'

# Creating the swap_file space . Weblogic demands 500MB of minimum swap_file
#swap_file '/mnt/swap_file' do
#  size 1024
#end

script 'create swapfile' do
  interpreter 'bash'
  not_if { File.exists?('/mnt/swap') }
  code <<-eof
    dd if=/dev/zero of=/mnt/swap bs=1M count=6096 &&
    chmod 600 /mnt/swap &&
    mkswap /mnt/swap
    swapon /mnt/swap
  eof
end

mount '/dev/null' do  # swap file entry for fstab
  action :enable  # cannot mount; only add to fstab
  device '/mnt/swap'
  fstype 'swap'
end

script 'activate swap' do
  interpreter 'bash'
  code 'swapon -a'
end