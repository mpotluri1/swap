#
# Cookbook:: swap
# Recipe:: default
#
# Copyright:: 2017, REAN Cloud LLC, All Rights Reserved.

# Creating the swap space . Weblogic demands 500MB of minimum swap
swap_file '/mnt/swap' do
  size 1024
end

